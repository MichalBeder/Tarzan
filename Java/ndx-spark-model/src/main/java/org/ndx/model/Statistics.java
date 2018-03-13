package org.ndx.model;

import org.ndx.model.pcap.ConversationModel.FlowAttributes;
import org.ndx.model.pcap.FlowModel.FlowKey;
import org.ndx.model.pcap.PcapPacket;

import java.util.Date;

public class Statistics {
    private static long MILISECONDS_TO_SECONDS = 1000L;

    private static java.text.DecimalFormat df = new java.text.DecimalFormat("#.###");

    public static Date ticksToDate(long ticks) {
        return new Date(ticks);
    }

    public static double timestampToSeconds(long timestamp) {
        return (((double)timestamp) / (double) MILISECONDS_TO_SECONDS);
    }
 
    public static FlowAttributes merge (FlowAttributes x, FlowAttributes y) {
        FlowAttributes.Builder builder  = FlowAttributes.newBuilder();
        builder.setFirstSeen(Math.min(x.getFirstSeen(),y.getFirstSeen()));
        builder.setLastSeen(Math.max(x.getLastSeen(),y.getLastSeen()));
        builder.setPackets(x.getPackets() + y.getPackets());
        builder.setOctets(x.getOctets() + y.getOctets());
        builder.setMaximumPayloadSize(Math.max(x.getMaximumPayloadSize(),y.getMaximumPayloadSize()));
        builder.setMinimumPayloadSize(Math.min(x.getMinimumPayloadSize(),y.getMinimumPayloadSize()));
        builder.setMeanPayloadSize((x.getMeanPayloadSize() + y.getMeanPayloadSize()) / 2); 
        return builder.build();
    }

    public static FlowAttributes fromPacket(Packet p) {
        Long first = ((Number)p.get(PcapPacket.TIMESTAMP)).longValue();
        Long last = ((Number)p.get(PcapPacket.TIMESTAMP)).longValue();
        Long octets = ((Number)p.get(PcapPacket.LEN)).longValue();
      
        FlowAttributes.Builder builder  = FlowAttributes.newBuilder();
        builder.setFirstSeen(first);
        builder.setLastSeen(last);
        builder.setPackets(1);
        builder.setOctets(octets);
        builder.setMaximumPayloadSize(octets.intValue());
        builder.setMinimumPayloadSize(octets.intValue());
        builder.setMeanPayloadSize(octets.intValue());
        return builder.build();
    }

    // Formats 
    public static String format(String flowkey, FlowAttributes attributes) {
        Date first = ticksToDate(attributes.getFirstSeen());
     
        Date last = ticksToDate(attributes.getLastSeen());
        float diff = ((float)(last.getTime() - first.getTime()))/1000;
        FlowKey fkey = PcapPacket.flowKeyParse(flowkey);
        String fkeystr = String.format("%5s %20s -> %20s ", 
            fkey.getProtocol().toStringUtf8(), 
            fkey.getSourceAddress().toStringUtf8() + ":" + fkey.getSourceSelector().toStringUtf8(), 
            fkey.getDestinationAddress().toStringUtf8() + ":" + fkey.getDestinationSelector().toStringUtf8());
        return String.format("%30s %12s %60s %10d %15d %5d",first.toString(), df.format(diff), fkeystr,
                attributes.getPackets(), attributes.getOctets(), 1 );
    }
}
