package org.ndx.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.pcap.ConversationModel.FlowAttributes;
import org.ndx.model.pcap.FlowModel.FlowKey;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.Map;

public class Statistics {

    private static final Log LOG = LogFactory.getLog(Statistics.class);

    private static final long MILISECONDS_TO_SECONDS = 1000L;

    private static java.text.DecimalFormat df = new java.text.DecimalFormat("#.###");

    public static Date ticksToDate(long ticks) {
        return new Date(ticks);
    }

    public static double timestampToSeconds(long timestamp) {
        return (((double)timestamp) / (double) MILISECONDS_TO_SECONDS);
    }

    public static Map<String, Integer> mergeMaps(Map<String, Integer> map1, Map<String, Integer> map2) {
        map2.forEach((k, v) -> map1.merge(k, v, (v1, v2) -> v1 + v2));
        return map1;
    }

    public static String lanOrWan(String srcIp, String dstIp) {
        String lanWan = "wan";
        try {
            if (ipAddrPrivate(srcIp) && ipAddrPrivate(dstIp)) {
                lanWan = "lan";
            }
        } catch (UnknownHostException e) {
            LOG.warn("Input string is not an ip address.");
            lanWan = "";
        }
        return lanWan;
    }

    private static boolean ipAddrPrivate(String ip) throws UnknownHostException {
        boolean isPrivate = false;
        InetAddress address = InetAddress.getByName(ip);

        if (address.isAnyLocalAddress() ||
            address.isLinkLocalAddress() ||
            address.isLoopbackAddress() ||
            address.isMCLinkLocal() ||
            address.isMCNodeLocal() ||
            address.isMCOrgLocal() ||
            address.isMCSiteLocal()) {
            isPrivate = true;
        }

        // Site local address is deprecated in ipv6. New implementations
        // must treat this prefix as Global Unicast.
        if (address instanceof Inet4Address && address.isSiteLocalAddress()) {
            isPrivate = true;
        }
        return isPrivate;
    }

    public static String getEmailProtocol(String srcPort, String dstPort) {
        String email = "";
        if (srcPort.equals(Integer.toString(Packet.POP3_PORT_1)) ||
                dstPort.equals(Integer.toString(Packet.POP3_PORT_1))) {
            email = "pop3";
        } else if (srcPort.equals(Integer.toString(Packet.IMAP_PORT_1)) ||
                dstPort.equals(Integer.toString(Packet.IMAP_PORT_1))) {
            email = "imap";
        } else if (srcPort.equals(Integer.toString(Packet.SMTP_PORT_1)) ||
                dstPort.equals(Integer.toString(Packet.SMTP_PORT_1)) ||
                srcPort.equals(Integer.toString(Packet.SMTP_PORT_2)) ||
                dstPort.equals(Integer.toString(Packet.SMTP_PORT_2))) {
            email = "smtp";
        } else if (srcPort.equals(Integer.toString(Packet.POP3_PORT_2)) ||
                dstPort.equals(Integer.toString(Packet.POP3_PORT_2))) {
            email = "spop3";
        } else if (srcPort.equals(Integer.toString(Packet.IMAP_PORT_2)) ||
                dstPort.equals(Integer.toString(Packet.IMAP_PORT_2))) {
            email = "imaps";
        } else if (srcPort.equals(Integer.toString(Packet.SMTP_PORT_3)) ||
                dstPort.equals(Integer.toString(Packet.SMTP_PORT_3))) {
            email = "smtps";
        }
        return email;
    }

    public static String getService(String srcPort, String dstPort) {
        String port = "";
        try {
            port = Integer.parseInt(srcPort) < Integer.parseInt(dstPort) ? srcPort : dstPort;
        } catch (NumberFormatException e) {
            LOG.warn("Given port is not a number.");
        }
        return port;
    }

    public static String getDirection(String srcPort, String dstPort) {
        String direction = "";
        try {
            direction = Integer.parseInt(srcPort) < Integer.parseInt(dstPort) ? "down" : "up";
        } catch (NumberFormatException e) {
            LOG.warn("Given port is not a number.");
        }
        return direction;
    }

    public static FlowAttributes merge(FlowAttributes x, FlowAttributes y) {
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
        Long first = 0L;
        Long last = 0L;
        Long octets = 0L;
        if (p.containsKey(Packet.TIMESTAMP)) {
            first = ((Number)p.get(Packet.TIMESTAMP)).longValue();
            last = ((Number)p.get(Packet.TIMESTAMP)).longValue();
        }
        if (p.containsKey(Packet.FRAME_LENGTH)) {
            octets = ((Number)p.get(Packet.FRAME_LENGTH)).longValue();
        }
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
        FlowKey fkey = Packet.flowKeyParse(flowkey);
        String fkeystr = String.format("%5s %20s -> %20s ", 
            fkey.getProtocol().toStringUtf8(), 
            fkey.getSourceAddress().toStringUtf8() + ":" + fkey.getSourceSelector().toStringUtf8(), 
            fkey.getDestinationAddress().toStringUtf8() + ":" + fkey.getDestinationSelector().toStringUtf8());
        return String.format("%30s %12s %60s %10d %15d %5d",first.toString(), df.format(diff), fkeystr,
                attributes.getPackets(), attributes.getOctets(), 1 );
    }
}
