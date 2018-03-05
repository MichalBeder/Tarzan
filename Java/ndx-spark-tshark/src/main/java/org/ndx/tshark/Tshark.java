package org.ndx.tshark;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.lib.input.TextInputFormat;
import org.apache.spark.SparkConf;
import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.ndx.model.*;
import org.ndx.pcap.PcapInputFormat;
import scala.Tuple2;

import java.util.function.Function;

public class Tshark {

    public static JavaRDD<JsonPacket> statsFromJson(JavaSparkContext sc, String path) {
        JavaPairRDD<LongWritable, Text> lines = sc.newAPIHadoopFile(path,
                        TextInputFormat.class, LongWritable.class, Text.class, new Configuration());
//        JavaRDD<String> packets = lines.map(x -> JsonPacket.parsePacket(x._2));
        //TODO filter x._2.toString().startsWith("{\"timestamp")
        JavaRDD<String> jsons = lines.filter(x -> !x._2.toString().startsWith("{\"index")).map(x -> x._2.toString());
        JavaRDD<JsonPacket> packets = jsons.map(JsonPacket::parsePacket);

//        JavaPairRDD<String, JsonPacket> flows = packets.mapToPair(x -> new Tuple2<>(x.getFlowString(), x));
//        JavaPairRDD<String, ConversationModel.FlowAttributes> stats =
//                flows.mapToPair(x -> new Tuple2<>(x._1, Statistics.fromPacket(x._2)))
//                        .reduceByKey(Statistics::merge);
        return packets;
    }

    public static JavaRDD<Packet> statsFromPcap(JavaSparkContext sc, String path) {
        JavaPairRDD<LongWritable, ObjectWritable> frames = sc.hadoopFile(path,
                PcapInputFormat.class, LongWritable.class, ObjectWritable.class);

        JavaRDD<Packet> packets = frames.map(x -> Packet.parsePacket((PacketModel.RawFrame) x._2.get()));

//        JavaPairRDD<String, Packet> flows = packets.mapToPair(x -> new Tuple2<>(x.getFlowString(), x));
//        JavaPairRDD<String, ConversationModel.FlowAttributes> stats =
//                flows.mapToPair(x -> new Tuple2<>(x._1, Statistics.fromPacket(x._2)))
//                        .reduceByKey(Statistics::merge);
        return packets;
    }

    public static JavaPairRDD<String, ConversationModel.FlowAttributes> testJsonFlows(JavaSparkContext sc, String path) {
        JavaRDD<JsonPacket> packets = statsFromJson(sc, path);
        JavaPairRDD<String, JsonPacket> flows = packets.mapToPair(x -> new Tuple2<>(x.getFlowString(), x));
        JavaPairRDD<String, ConversationModel.FlowAttributes> stats =
                flows.mapToPair(x -> new Tuple2<>(x._1, Statistics.fromPacket(x._2)))
                        .reduceByKey(Statistics::merge);
        return stats;
    }

    public static JavaPairRDD<String, ConversationModel.FlowAttributes> testPcapFlows(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = statsFromPcap(sc, path);
        JavaPairRDD<String, Packet> flows = packets.mapToPair(x -> new Tuple2<>(x.getFlowString(), x));
        JavaPairRDD<String, ConversationModel.FlowAttributes> stats =
                flows.mapToPair(x -> new Tuple2<>(x._1, Statistics.fromPacket(x._2)))
                        .reduceByKey(Statistics::merge);
        return stats;
    }

    public static void testJsonPackCnt(JavaSparkContext sc, String path) {
        JavaRDD<JsonPacket> packets = statsFromJson(sc, path);
        ConversationModel.FlowAttributes capinfo = packets.map(Statistics::fromPacket).reduce(Statistics::merge);
        System.out.println("Json: no of packets: " + capinfo.getPackets());
        System.out.println("Json: First packet time: " + Statistics.ticksToDate(capinfo.getFirstSeen()));
        System.out.println("Json: Last packet time: " + Statistics.ticksToDate(capinfo.getLastSeen()));
        System.out.println("Json: Data byte rate: " + capinfo.getOctets() / Statistics.ticksToSeconds((capinfo.getLastSeen() - capinfo.getFirstSeen())));
        System.out.println("Json: Data bit rate " + (capinfo.getOctets() / Statistics.ticksToSeconds((capinfo.getLastSeen() - capinfo.getFirstSeen()))) * 8);
        System.out.println("Json: Average packet size: " + capinfo.getMeanPayloadSize());
        System.out.println("Json: Average packet rate: " + capinfo.getPackets() / ((capinfo.getLastSeen() - capinfo.getFirstSeen()) / 10000000));

    }

    public static void testPcapPackCnt(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = statsFromPcap(sc, path);
        ConversationModel.FlowAttributes capinfo = packets.map(Statistics::fromPacket).reduce(Statistics::merge);
        System.out.println("Pcap: No of packets: " + capinfo.getPackets());
        System.out.println("Pcap: First packet time: " + Statistics.ticksToDate(capinfo.getFirstSeen()));
        System.out.println("Pcap: Last packet time: " + Statistics.ticksToDate(capinfo.getLastSeen()));
        System.out.println("Pcap: Data byte rate: " + capinfo.getOctets() / Statistics.ticksToSeconds((capinfo.getLastSeen() - capinfo.getFirstSeen())));
        System.out.println("Pcap: Data bit rate " + (capinfo.getOctets() / Statistics.ticksToSeconds((capinfo.getLastSeen() - capinfo.getFirstSeen()))) * 8);
        System.out.println("Pcap: Average packet size: " + capinfo.getMeanPayloadSize());
        System.out.println("Pcap: Average packet rate: " + capinfo.getPackets() / ((capinfo.getLastSeen() - capinfo.getFirstSeen()) / 10000000));

    }

}
