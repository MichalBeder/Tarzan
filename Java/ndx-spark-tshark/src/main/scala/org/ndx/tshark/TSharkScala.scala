package org.ndx.tshark

import java.io.IOException
import java.util

import org.apache.commons.io.FilenameUtils
import org.apache.commons.logging.LogFactory
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.io.{LongWritable, ObjectWritable, Text}
import org.apache.hadoop.mapreduce.lib.input.TextInputFormat
import org.ndx.model.json.JsonPacket
import org.ndx.model.pcap.PcapPacket
import org.ndx.pcap.PcapInputFormat
import org.ndx.model.pcap.PacketModel
import org.apache.spark.SparkContext
import org.apache.spark.rdd.RDD
import org.ndx.model.{Packet, Statistics}
import org.apache.spark.sql.SparkSession
import org.ndx.model.parsers.applayer.HttpHelper

import scala.collection.JavaConverters._
import scala.collection.JavaConversions._
import scala.collection.mutable


class TSharkScala {}

object TSharkScala {

    private val Log = LogFactory.getLog(classOf[TSharkScala])
    private val Pcap = "pcap"
    private val Cap = "cap"
    private val Json = "json"

    /* Flow analysis. */

    def getFlows(packets: RDD[Packet]): RDD[(String, Iterable[Packet])] = {
        packets.map((x: Packet) => (x.getFlowString, x)).groupByKey
    }

    def getFlowStatistics(packets: RDD[Packet]): RDD[FlowStatistics] = {
        val stats = packets.filter(x => {
            val protocol = Option(x.get(Packet.PROTOCOL)).getOrElse("")
            (protocol.equals(Packet.PROTOCOL_TCP) || protocol.equals(Packet.PROTOCOL_UDP)) &&
                 !Option(x.get(Packet.FRAGMENT)).getOrElse(true).asInstanceOf[Boolean]
            })
            .map(x => (x.getFlowString, x))
            .map(x => (x._1, Statistics.fromPacket(x._2)))
            .reduceByKey((acc, stats) => Statistics.merge(acc, stats))

        stats.map(x => {
            val flowKey = Packet.flowKeyParse(x._1)
            val srcAddr = flowKey.getSourceAddress.toStringUtf8
            val destAddr = flowKey.getDestinationAddress.toStringUtf8
            val srcPort = flowKey.getSourceSelector.toStringUtf8
            val destPort = flowKey.getDestinationSelector.toStringUtf8
            FlowStatistics(
                new java.sql.Timestamp(Statistics.ticksToDate(x._2.getFirstSeen).getTime),
                new java.sql.Timestamp(Statistics.ticksToDate(x._2.getLastSeen).getTime),
                flowKey.getProtocol.toStringUtf8,
                srcAddr,
                srcPort,
                destAddr,
                destPort,
                Statistics.getService(flowKey.getSourceSelector.toStringUtf8,
                    flowKey.getDestinationSelector.toStringUtf8),
                Statistics.getDirection(flowKey.getSourceSelector.toStringUtf8,
                    flowKey.getDestinationSelector.toStringUtf8),
                x._2.getPackets,
                x._2.getOctets,
                Statistics.lanOrWan(srcAddr, destAddr),
                Statistics.getEmailProtocol(srcPort, destPort)
            )})
    }

    def registerFlowStatistics(viewName: String, packets: RDD[Packet], spark: SparkSession): Unit = {
        import spark.implicits._
        val stats = getFlowStatistics(packets)
        stats.toDF().createOrReplaceTempView(viewName)
    }

    /* Packet content analysis. */

    def getHttpHostnames(packets: RDD[Packet]): RDD[Url] = {
        packets.filter((x: Packet) => Option(x.get(Packet.HTTP_URL)).isDefined)
        .map(packet => Url(HttpHelper.getHostFromUrl(packet.get(Packet.HTTP_URL).asInstanceOf[String])))
    }

    def registerHttpHostnames(viewName: String, packets: RDD[Packet], spark: SparkSession): Unit = {
        import spark.implicits._
        val urls = getHttpHostnames(packets)
        urls.toDF().createOrReplaceTempView(viewName)
    }

    def getDnsData(packets: RDD[Packet]): RDD[DnsDataRaw] = {
        getDnsPackets(packets)
            .filter(x => x.containsKey(Packet.DNS_ID) && x.containsKey(Packet.DNS_IS_RESPONSE))
            .flatMap(x => {
                val flow: String = x.getFlowString
                val id: Integer = x.get(Packet.DNS_ID).asInstanceOf[Integer]
                val isResponse: Boolean = x.get(Packet.DNS_IS_RESPONSE).asInstanceOf[Boolean]
                val records: Seq[String] = if (isResponse)
                        x.get(Packet.DNS_ANSWERS).asInstanceOf[util.ArrayList[String]].toSeq
                    else x.get(Packet.DNS_QUERIES).asInstanceOf[util.ArrayList[String]].toSeq
                if (records.isEmpty) { records.add("") }
                records.map(record => DnsDataRaw(flow, id, isResponse, record))
            })
    }

    def registerDnsData(viewName: String, packets: RDD[Packet], spark: SparkSession): Unit = {
        import spark.implicits._
        val dnsData = getDnsData(packets).map(x => {
            val splits = x.record.split(",")
            DnsData(x.flow, x.id, x.isResponse, splits.lift(0).getOrElse(""), splits.lift(1).getOrElse(""),
                splits.lift(2).getOrElse(""), splits.lift(3).getOrElse(""))
        })
        dnsData.toDF().createOrReplaceTempView(viewName)
    }

    def getKeywords(packets: RDD[Packet], keywords: List[String], sc: SparkContext): RDD[Keyword] = {
        val javaKeywords = keywords.asJava
        val keywordsMap: mutable.Map[String, Integer] = packets
            .map((x: Packet) => Option(x.findKeyWords(javaKeywords)).getOrElse(new util.HashMap[String, Integer]))
            .reduce((x, y) => Statistics.mergeMaps(x, y)).asScala
        sc.parallelize(keywordsMap.toSeq).map(x => Keyword(x._1, x._2))
    }

    def registerKeywords(viewName: String, packets: RDD[Packet], keywords: List[String],
                         spark: SparkSession, sc: SparkContext): Unit = {
        import spark.implicits._
        val kws = getKeywords(packets, keywords, sc)
        kws.toDF().createOrReplaceTempView(viewName)
    }

    def getCipherSuites(packets: RDD[Packet]): RDD[CipherSuite] = {
        packets.filter(x => x.containsKey(Packet.SSL_CIPHER_SUITES))
            .flatMap(x => x.get(Packet.SSL_CIPHER_SUITES)
                .asInstanceOf[util.ArrayList[String]].toSeq
                .map(x => CipherSuite(x)))
    }

    def registerCipherSuites(viewName: String, packets: RDD[Packet], spark: SparkSession): Unit = {
        import spark.implicits._
        val cs = getCipherSuites(packets)
        cs.toDF().createOrReplaceTempView(viewName)
    }

    def getDnsLatency(packets: RDD[Packet]): RDD[DnsLatency] = {
        getDnsPackets(packets)
            .filter(x => x.containsKey(Packet.DNS_ID) && x.containsKey(Packet.DNS_IS_RESPONSE)
                && x.containsKey(Packet.TIMESTAMP) && x.containsKey(Packet.SRC)
                && x.containsKey(Packet.DST) && x.containsKey(Packet.DST_PORT))
            .map(x => (x.getSessionString + x.get(Packet.DNS_ID).asInstanceOf[Int], x))
            .groupByKey()
            .map(x => x._2)
            .filter(x => x.size == 2)
            .map(x => (x.toSeq.lift(0), x.toSeq.lift(1)))
            .filter(x => x._1.get(Packet.DNS_IS_RESPONSE).asInstanceOf[Boolean] ^
                x._2.get(Packet.DNS_IS_RESPONSE).asInstanceOf[Boolean])
            .map(x => {
                val address: String = if (x._1.get(Packet.DNS_IS_RESPONSE).asInstanceOf[Boolean])
                        x._1.get(Packet.SRC).asInstanceOf[String]
                    else x._1.get(Packet.DST).asInstanceOf[String]
                val latency = Math.abs(x._1.get(Packet.TIMESTAMP).asInstanceOf[Long] -
                    x._2.get(Packet.TIMESTAMP).asInstanceOf[Long])
                DnsLatency(address, latency)
            })
    }

    def getTcpFlows(packets: RDD[Packet]): RDD[(String, Iterable[TcpPacket])] = {
        val tcpPackets: RDD[TcpPacket] =
            packets.filter(x => Option(x.get(Packet.PROTOCOL)).getOrElse("").equals(Packet.PROTOCOL_TCP)
                && !Option(x.get(Packet.FRAGMENT)).getOrElse(true).asInstanceOf[Boolean]
                && x.containsKey(Packet.TIMESTAMP) && x.containsKey(Packet.TCP_FLAG_NS)
                && x.containsKey(Packet.TCP_FLAG_CWR) && x.containsKey(Packet.TCP_FLAG_ECE)
                && x.containsKey(Packet.TCP_FLAG_URG) && x.containsKey(Packet.TCP_FLAG_ACK)
                && x.containsKey(Packet.TCP_FLAG_PSH) && x.containsKey(Packet.TCP_FLAG_RST)
                && x.containsKey(Packet.TCP_FLAG_SYN) && x.containsKey(Packet.TCP_FLAG_FIN)
                && x.containsKey(Packet.TCP_SEQ))
                .map(x => {
                    TcpPacket(
                        x.getFlowString,
                        new java.sql.Timestamp(x.get(Packet.TIMESTAMP).asInstanceOf[Long]),
                        x.get(Packet.TCP_FLAG_NS).asInstanceOf[Boolean],
                        x.get(Packet.TCP_FLAG_CWR).asInstanceOf[Boolean],
                        x.get(Packet.TCP_FLAG_ECE).asInstanceOf[Boolean],
                        x.get(Packet.TCP_FLAG_URG).asInstanceOf[Boolean],
                        x.get(Packet.TCP_FLAG_ACK).asInstanceOf[Boolean],
                        x.get(Packet.TCP_FLAG_PSH).asInstanceOf[Boolean],
                        x.get(Packet.TCP_FLAG_RST).asInstanceOf[Boolean],
                        x.get(Packet.TCP_FLAG_SYN).asInstanceOf[Boolean],
                        x.get(Packet.TCP_FLAG_FIN).asInstanceOf[Boolean],
                        x.get(Packet.TCP_SEQ).asInstanceOf[Long],
                        x.get(Packet.FRAME_LENGTH).asInstanceOf[Integer],
                        Option(x.get(Packet.TCP_HEX_PAYLOAD)).getOrElse("").asInstanceOf[String])
                })
        tcpPackets.map((x: TcpPacket) => (x.flow, x))
            .groupByKey
            .mapValues(_.toSeq.sortBy(_.timeStamp.getTime))
    }

    private def getDnsPackets(packets: RDD[Packet]): RDD[Packet] = {
        packets.filter(x => Option(x.get(Packet.APP_LAYER_PROTOCOL)).getOrElse("")
            .equals(Packet.AppLayerProtocols.DNS))
    }

    /* Packets - reading and parsing. */

    def getPackets(sc: SparkContext, path: String): RDD[Packet] = {
        var packets: RDD[Packet] = null
        try
            packets = readInputFiles(sc, path)
        catch {
            case io: IOException =>
                Log.error(io.getMessage)
        }
        packets
    }

    private def readInputFiles(sc: SparkContext, path: String): RDD[Packet] = {
        FilenameUtils.getExtension(path) match {
            case Pcap | Cap => pcapToPacket(sc, path)
            case Json => jsonToPacket(sc, path)
            case _ =>
                throw new IOException("Not supported input file format.")
        }
    }

    private def jsonToPacket(sc: SparkContext, path: String): RDD[Packet] = {
        val lines = sc.newAPIHadoopFile(path, classOf[TextInputFormat], classOf[LongWritable], classOf[Text],
            new Configuration)
        val jsons = lines.filter(x => x._2.toString.startsWith("{\"time")).map(x => x._2.toString)
        jsons.map((jsonFrame: String) => {
                val packet: Packet = new JsonPacket
                packet.parsePacket(jsonFrame)
                packet
        })
    }

    private def pcapToPacket(sc: SparkContext, path: String): RDD[Packet] = {
        val frames = sc.hadoopFile(path, classOf[PcapInputFormat], classOf[LongWritable], classOf[ObjectWritable])
        frames.map(pcapFrame => {
                val packet = new PcapPacket
                packet.parsePacket(pcapFrame._2.get.asInstanceOf[PacketModel.RawFrame])
                packet
        })
    }

}
