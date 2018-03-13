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
import org.ndx.model.json.JsonPacket;
import org.ndx.model.pcap.ConversationModel;
import org.ndx.model.pcap.PacketModel;
import org.ndx.model.pcap.PcapPacket;
import org.ndx.pcap.PcapInputFormat;
import scala.Tuple2;

import java.io.IOException;
import java.util.ArrayList;

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
        return jsons.map(jsonFrame -> {
            Packet packet = new JsonPacket();
            packet.parsePacket(jsonFrame);
            return packet;
        });
    }

    private static JavaRDD<Packet> pcapToPacket(JavaSparkContext sc, String path) {
        JavaPairRDD<LongWritable, ObjectWritable> frames = sc.hadoopFile(path,
                PcapInputFormat.class, LongWritable.class, ObjectWritable.class);
        return frames.map(pcapFrame -> {
            Packet packet = new PcapPacket();
            packet.parsePacket((PacketModel.RawFrame) pcapFrame._2.get());
            return packet;
        });
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

    @SuppressWarnings("unchecked")
    public static void testDnsData(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets;
        try {
            packets = readInputFiles(sc, path);
        } catch (IOException e) {
            LOG.error("Not supported input file format.");
            return;
        }
//        JavaRDD<String> dnsAnswCnts = packets.map(Packet::getDnsAnswCnt);
        packets.collect().forEach(x -> {
            if (x.get(Packet.APP_LAYER_PROTOCOL) != Packet.ApplicationLayerProtocols.DNS) {
                return;
            }
            String qOrR = "Query";
            if ((int) x.get(Packet.DNS_QUERY_OR_RESPONSE) == 1) {
                qOrR = "Response";
            }
            System.out.println("Q/R: " + qOrR);
            System.out.println("ID: " + x.get(Packet.DNS_ID));
            System.out.println("Query cnt: " + x.get(Packet.DNS_QUERY_CNT));
            System.out.println("Answer cnt: " + x.get(Packet.DNS_ANSWER_CNT));
            ArrayList<String> queries = (ArrayList<String>) x.get(Packet.DNS_QUERIES);
            ArrayList<String> answers = (ArrayList<String>) x.get(Packet.DNS_ANSWERS);
            for (String q : queries) {
                System.out.println(q);
            }
            for (String a : answers) {
                System.out.println(a);
            }
            System.out.println();
        });
    }
}
