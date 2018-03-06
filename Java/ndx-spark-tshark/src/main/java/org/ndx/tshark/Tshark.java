package org.ndx.tshark;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.lib.input.TextInputFormat;
import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.ndx.model.*;
import org.ndx.pcap.PcapInputFormat;
import scala.Tuple2;

import java.io.IOException;

import static org.ndx.model.Statistics.timestampToSeconds;

public class Tshark {
    private static final Log LOG = LogFactory.getLog(Packet.class);
    private static final String PCAP = "pcap";
    private static final String CAP = "cap";
    private static final String JSON = "json";

    private static JavaRDD<Packet> readInputFiles(JavaSparkContext sc, String path) throws IOException {
        JavaRDD<Packet> packets;
        switch (FilenameUtils.getExtension(path)) {
            case PCAP:
            case CAP:
                packets = pcapToPacket(sc, path);
                break;
            case JSON:
                packets = jsonToPacket(sc, path);
                break;
            default:
                throw new IOException("Not supported input file format.");
        }
        return packets;
    }

    private static JavaRDD<Packet> jsonToPacket(JavaSparkContext sc, String path) {
        JavaPairRDD<LongWritable, Text> lines = sc.newAPIHadoopFile(path,
                TextInputFormat.class, LongWritable.class, Text.class, new Configuration());
        //TODO filter x._2.toString().startsWith("{\"timestamp")
        JavaRDD<String> jsons = lines.filter(x -> !x._2.toString().startsWith("{\"index")).map(x -> x._2.toString());
        return jsons.map(Packet::parsePacket);
    }

    private static JavaRDD<Packet> pcapToPacket(JavaSparkContext sc, String path) {
        JavaPairRDD<LongWritable, ObjectWritable> frames = sc.hadoopFile(path,
                PcapInputFormat.class, LongWritable.class, ObjectWritable.class);
        return frames.map(x -> Packet.parsePacket((PacketModel.RawFrame) x._2.get()));
    }

//        JavaPairRDD<String, PcapPacket> flows = packets.mapToPair(x -> new Tuple2<>(x.getFlowString(), x));
//        JavaPairRDD<String, ConversationModel.FlowAttributes> stats =
//                flows.mapToPair(x -> new Tuple2<>(x._1, Statistics.fromPacket(x._2)))
//                        .reduceByKey(Statistics::merge);

    public static JavaPairRDD<String, ConversationModel.FlowAttributes> testFlows(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets;
        try {
            packets = readInputFiles(sc, path);
        } catch (IOException e) {
            LOG.error("Not supported input file format.");
            return null;
        }

        JavaPairRDD<String, Packet> flows = packets.mapToPair(x -> new Tuple2<>(x.getFlowString(), x));
        return flows.mapToPair(x -> new Tuple2<>(x._1, Statistics.fromPacket(x._2))).reduceByKey(Statistics::merge);
    }

    public static void testPacketInfo(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets;
        try {
            packets = readInputFiles(sc, path);
        } catch (IOException e) {
            LOG.error("Not supported input file format.");
            return;
        }

        ConversationModel.FlowAttributes capinfo = packets.map(Statistics::fromPacket).reduce(Statistics::merge);
        System.out.println("Json: no of packets: " + capinfo.getPackets());
        System.out.println("Json: First packet time: " + Statistics.ticksToDate(capinfo.getFirstSeen()));
        System.out.println("Json: Last packet time: " + Statistics.ticksToDate(capinfo.getLastSeen()));
        System.out.println("Json: Data byte rate: " + capinfo.getOctets() / timestampToSeconds(
                (capinfo.getLastSeen() - capinfo.getFirstSeen())));
        System.out.println("Json: Data bit rate " + (capinfo.getOctets() / timestampToSeconds(
                (capinfo.getLastSeen() - capinfo.getFirstSeen()))) * 8);
        System.out.println("Json: Average packet size: " + capinfo.getMeanPayloadSize());
        System.out.println("Json: Average packet rate: " + capinfo.getPackets() /
                timestampToSeconds(capinfo.getLastSeen() - capinfo.getFirstSeen()));
    }
}
