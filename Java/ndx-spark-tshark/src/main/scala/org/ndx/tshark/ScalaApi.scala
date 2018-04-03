package org.ndx.tshark

import java.io.IOException

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
import org.ndx.model.Packet
import org.apache.spark.sql.SparkSession

class ScalaApi {}

object ScalaApi {

    private val Log = LogFactory.getLog(classOf[ScalaApi])
    private val Pcap = "pcap"
    private val Cap = "cap"
    private val Json = "json"


    def registerHttpUrls(packets: RDD[Packet], spark: SparkSession): Unit = {
        import spark.implicits._
        val urls = packets.filter(packet => Option(packet.get(Packet.HTTP_URL)).isDefined)
            .map(packet => Url(packet.get(Packet.HTTP_URL).asInstanceOf[String]))
        urls.toDF().createOrReplaceTempView("httpUrls")
    }

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
        val jsons = lines.filter(x => x._2.toString.startsWith("{\"timestamp")).map(x => x._2.toString)
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
