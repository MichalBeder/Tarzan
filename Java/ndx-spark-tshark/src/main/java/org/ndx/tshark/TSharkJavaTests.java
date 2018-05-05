package org.ndx.tshark;

import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.ndx.model.Packet;
import org.ndx.model.Statistics;
import org.ndx.model.pcap.ConversationModel;
import scala.Tuple2;

import java.util.ArrayList;

import static org.ndx.model.Statistics.timestampToSeconds;

@SuppressWarnings("unchecked")
public class TSharkJavaTests {

    public static JavaPairRDD<String, ConversationModel.FlowAttributes> testFlows(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = TSharkJava.getPackets(sc, path);
        if (packets == null) return null;

        JavaPairRDD<String, Packet> flows = packets.mapToPair(x -> new Tuple2<>(x.getFlowString(), x));
        return flows.mapToPair(x -> new Tuple2<>(x._1, Statistics.fromPacket(x._2))).reduceByKey(Statistics::merge);
    }

    public static void testPacketInfo(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = TSharkJava.getPackets(sc, path);
        if (packets == null) return;

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

    public static void testHttpData(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = TSharkJava.getPackets(sc, path);
        if (packets == null) return;
        packets.collect().forEach(x -> {
            if (x.get(Packet.APP_LAYER_PROTOCOL) != Packet.AppLayerProtocols.HTTP)
                return;
            System.out.println("Packet number: " + (int) x.get(Packet.NUMBER));
            boolean isResponse = (boolean) x.get(Packet.HTTP_IS_RESPONSE);
            if (isResponse) {
                System.out.println("Req/Res: Response");
            } else {
                System.out.println("Req/Res: Request");
                System.out.println("URL: " + x.get(Packet.HTTP_URL));
                System.out.println("Method: " + x.get(Packet.HTTP_METHOD));
            }
            System.out.println("Version: " + x.get(Packet.HTTP_VERSION));
            System.out.println();
        });
    }

    public static void testTcpPayload(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = TSharkJava.getPackets(sc, path);
        if (packets == null) return;
        packets.collect().forEach(x -> {
            if (!x.get(Packet.PROTOCOL).equals(Packet.PROTOCOL_TCP))
                return;
            System.out.println("Packet number: " + (int) x.get(Packet.NUMBER));
            String payload = (String) x.get(Packet.TCP_HEX_PAYLOAD);
            if (payload != null) {
                System.out.println(payload);
            }
            System.out.println();
        });
    }

    public static void testIpv6Packets(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = TSharkJava.getPackets(sc, path);
        if (packets == null) return;
        packets.collect().forEach(x -> {
            if ((Integer) x.get(Packet.IP_VERSION) != 6)
                return;
            System.out.println("Packet number: " + (int) x.get(Packet.NUMBER));
            String protocol = (String) x.get(Packet.PROTOCOL);
            System.out.println("Protocol: " + protocol);
            if ((boolean) x.get(Packet.FRAGMENT)) {
                System.out.println("Fragmented.");
            } else {
                System.out.println("Not fragmented.");
            }
            System.out.println();
        });
    }

    public static void testDnsData(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = TSharkJava.getPackets(sc, path);
        if (packets == null) return;
        packets.collect().forEach(x -> {
            if (x.get(Packet.APP_LAYER_PROTOCOL) != Packet.AppLayerProtocols.DNS) {
                return;
            }
            System.out.println("Packet number: " + (int) x.get(Packet.NUMBER));
            String qOrR = "Query";
            if ((boolean) x.get(Packet.DNS_IS_RESPONSE)) {
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

    public static void testAppProtocols(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = TSharkJava.getPackets(sc, path);
        if (packets == null) return;
        packets.collect().forEach(x -> {
            Packet.AppLayerProtocols protocol = (Packet.AppLayerProtocols)x.get(Packet.APP_LAYER_PROTOCOL);
            Integer no = (Integer) x.get(Packet.NUMBER);
            if (protocol == null || no == null) return;
            System.out.println("Packet " + no + ": " + protocol.name());
            System.out.println();
        });
    }

}
