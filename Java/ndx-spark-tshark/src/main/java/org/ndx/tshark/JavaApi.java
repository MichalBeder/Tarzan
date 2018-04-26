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
import org.ndx.model.pcap.PacketModel;
import org.ndx.model.pcap.PcapPacket;
import org.ndx.pcap.PcapInputFormat;
import scala.Tuple2;

import java.io.IOException;

public class JavaApi {
    private static final Log LOG = LogFactory.getLog(JavaApi.class);
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
        JavaRDD<String> jsons = lines.filter(x -> x._2.toString().startsWith("{\"timestamp")).map(x -> x._2.toString());
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

    public static JavaRDD<Packet> getRawPackets(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets;
        try {
            packets = readInputFiles(sc, path);
        } catch (IOException e) {
            LOG.error("Not supported input file format.");
            return null;
        }
        return packets;
    }

    public static JavaPairRDD<String, Iterable<Packet>> getFlows(JavaSparkContext sc, String path) {
        JavaRDD<Packet> packets = getRawPackets(sc, path);
        return packets != null ? packets.mapToPair(x -> new Tuple2<>(x.getFlowString(), x)).groupByKey() : null;
    }
}
