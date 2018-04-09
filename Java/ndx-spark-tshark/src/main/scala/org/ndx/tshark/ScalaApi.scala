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


class ScalaApi {}

object ScalaApi {

    private val Log = LogFactory.getLog(classOf[ScalaApi])
    private val Pcap = "pcap"
    private val Cap = "cap"
    private val Json = "json"

    /* Flow analysis. */

    def getFlows(packets: RDD[Packet]): RDD[(String, Iterable[Packet])] = {
        packets.map((x: Packet) => (x.getFlowString, x)).groupByKey()
    }

    def getFlowStatistics(packets: RDD[Packet]): RDD[FlowStatistics] = {
        val stats = packets.map(x => (x.getFlowString, x))
            .map(x => (x._1, Statistics.fromPacket(x._2)))
            .reduceByKey((acc, stats) => Statistics.merge(acc, stats))
       stats.map(x => {
            val flowKey = Packet.flowKeyParse(x._1)
            FlowStatistics(
                new java.sql.Date(Statistics.ticksToDate(x._2.getFirstSeen).getTime),
                new java.sql.Date(Statistics.ticksToDate(x._2.getLastSeen).getTime),
                flowKey.getProtocol.toStringUtf8,
                flowKey.getSourceAddress.toStringUtf8,
                flowKey.getSourceSelector.toStringUtf8,
                flowKey.getDestinationAddress.toStringUtf8,
                flowKey.getDestinationSelector.toStringUtf8,
                Statistics.getService(flowKey.getSourceSelector.toStringUtf8, flowKey.getDestinationSelector.toStringUtf8),
                Statistics.getDirection(flowKey.getSourceSelector.toStringUtf8, flowKey.getDestinationSelector.toStringUtf8),
                x._2.getPackets,
                x._2.getOctets
            )})
    }

    def registerFlowStatistics(packets: RDD[Packet], spark: SparkSession): Unit = {
        import spark.implicits._
        val stats = getFlowStatistics(packets)
        stats.toDF().createOrReplaceTempView("flowStatistics")
    }

    /* Packet content analysis. */

    def getHttpHostnames(packets: RDD[Packet]): RDD[Url] = {
        packets.filter((x: Packet) => Option(x.get(Packet.HTTP_URL)).isDefined)
        .map(packet => Url(HttpHelper.getHostfromUrl(packet.get(Packet.HTTP_URL).asInstanceOf[String])))
    }

    def registerHttpHostnames(packets: RDD[Packet], spark: SparkSession): Unit = {
        import spark.implicits._
        val urls = getHttpHostnames(packets)
        urls.toDF().createOrReplaceTempView("httpHostnames")
    }

    def getDnsData(packets: RDD[Packet]): RDD[DnsDataRaw] = {
        packets.filter(x => Option(x.get(Packet.APP_LAYER_PROTOCOL)).getOrElse("").equals(Packet.AppLayerProtocols.DNS))
            .filter(x => x.containsKey(Packet.DNS_ID) && x.containsKey(Packet.DNS_IS_RESPONSE))
            .flatMap(x => {
                val flow: String = x.getFlowString
                val id: Integer = x.get(Packet.DNS_ID).asInstanceOf[Integer]
                val isResponse: Boolean = x.get(Packet.DNS_IS_RESPONSE).asInstanceOf[Boolean]
                val rdata: Seq[String] = if (isResponse)
                    x.get(Packet.DNS_ANSWERS).asInstanceOf[util.ArrayList[String]].toSeq
                    else x.get(Packet.DNS_QUERIES).asInstanceOf[util.ArrayList[String]].toSeq
                if (rdata.isEmpty) { rdata.add("") }
                rdata.map(record => DnsDataRaw(flow, id, isResponse, record))
            })
    }

    def registerDnsData(packets: RDD[Packet], spark: SparkSession): Unit = {
        import spark.implicits._
        val dnsData = getDnsData(packets).map(x => {
            val splits = x.rdata.split(",")
            DnsData(x.flow, x.id, x.isResponse, splits.lift(0).getOrElse(""), splits.lift(1).getOrElse(""),
                splits.lift(2).getOrElse(""), splits.lift(3).getOrElse(""))
        })
        dnsData.toDF().createOrReplaceTempView("dnsData")
    }

    def getKeywords(packets: RDD[Packet], keywords: List[String], sc: SparkContext): RDD[Keyword] = {
        val javaKeywords = keywords.asJava
        val keywordsMap: mutable.Map[String, Integer] = packets
            .map((x: Packet) => Option(x.findKeyWords(javaKeywords)).getOrElse(new util.HashMap[String, Integer]))
            .reduce((x, y) => Statistics.mergeMaps(x, y)).asScala
        sc.parallelize(keywordsMap.toSeq).map(x => Keyword(x._1, x._2))
    }

    def registerKeywords(packets: RDD[Packet], keywords: List[String], spark: SparkSession, sc: SparkContext): Unit = {
        import spark.implicits._
        val kws = getKeywords(packets, keywords, sc)
        kws.toDF().createOrReplaceTempView("keywords")
    }

    def getTcpFlows(packets: RDD[Packet]): RDD[(String, Iterable[Packet])] = {
        packets.filter(x => Option(x.get(Packet.PROTOCOL)).getOrElse("").equals(Packet.PROTOCOL_TCP))
            .map((x: Packet) => (x.getFlowString, x)).groupByKey()
    }

    /* Packets - reading and parsing. */

    def getRawPackets(sc: SparkContext, path: String): RDD[Packet] = {
        var packets: RDD[Packet] = null
        try
            packets = readInputFiles(sc, path)
        catch {
            case _: IOException =>
                Log.error("Not supported input file format.")
                return null
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
