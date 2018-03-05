package org.ndx.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;

public class JsonPacket extends HashMap<String, Object> {
    protected static final long serialVersionUID = 8723206921174160147L;

    private static long UNIX_BASE_TICKS = 621355968000000000L;
    private static long TICKS_PER_MILLISECOND = 10000L;

    protected static Map<Integer, String> protocols;
    public static final Log LOG = LogFactory.getLog(JsonPacket.class);
    public static final String PROTOCOL_ICMP = "ICMP";
    public static final String PROTOCOL_TCP = "TCP";
    public static final String PROTOCOL_UDP = "UDP";
    public static final String PROTOCOL_FRAGMENT = "Fragment";
    static {
        protocols = new HashMap<Integer, String>();
        protocols.put(1, PROTOCOL_ICMP);
        protocols.put(6, PROTOCOL_TCP);
        protocols.put(17, PROTOCOL_UDP);
        protocols.put(44, PROTOCOL_FRAGMENT);
    }
    public static final String TIMESTAMP = "ts";
    public static final String TIMESTAMP_USEC = "ts_usec";
    public static final String TIMESTAMP_MICROS = "ts_micros";
    public static final String NUMBER = "number";

    public static final String TTL = "ttl";
    public static final String IP_VERSION = "ip_version";
    public static final String IP_HEADER_LENGTH = "ip_header_length";
    public static final String IP_FLAGS_DF = "ip_flags_df";
    public static final String IP_FLAGS_MF = "ip_flags_mf";
    public static final String IPV6_FLAGS_M = "ipv6_flags_m";
    public static final String FRAGMENT_OFFSET = "fragment_offset";
    public static final String FRAGMENT = "fragment";
    public static final String LAST_FRAGMENT = "last_fragment";
    public static final String PROTOCOL = "protocol";
    public static final String SRC = "src";
    public static final String DST = "dst";
    public static final String ID = "id";
    public static final String SRC_PORT = "src_port";
    public static final String DST_PORT = "dst_port";
    public static final String TCP_HEADER_LENGTH = "tcp_header_length";
    public static final String TCP_SEQ = "tcp_seq";
    public static final String TCP_ACK = "tcp_ack";
    public static final String LEN = "len";
    public static final String UDPSUM = "udpsum";
    public static final String UDP_LENGTH = "udp_length";
    public static final String TCP_FLAG_NS = "tcp_flag_ns";
    public static final String TCP_FLAG_CWR = "tcp_flag_cwr";
    public static final String TCP_FLAG_ECE = "tcp_flag_ece";
    public static final String TCP_FLAG_URG = "tcp_flag_urg";
    public static final String TCP_FLAG_ACK = "tcp_flag_ack";
    public static final String TCP_FLAG_PSH = "tcp_flag_psh";
    public static final String TCP_FLAG_RST = "tcp_flag_rst";
    public static final String TCP_FLAG_SYN = "tcp_flag_syn";
    public static final String TCP_FLAG_FIN = "tcp_flag_fin";
    public static final String REASSEMBLED_TCP_FRAGMENTS = "reassembled_tcp_fragments";
    public static final String REASSEMBLED_DATAGRAM_FRAGMENTS = "reassembled_datagram_fragments";
    public static final String PAYLOAD_LEN = "payload_len";

    public static final int ETHERNET_HEADER_SIZE = 14;
    public static final int ETHERNET_TYPE_OFFSET = 12;
    public static final int ETHERNET_TYPE_IP = 0x800;
    public static final int ETHERNET_TYPE_IPV6 = 0x86dd;
    public static final int ETHERNET_TYPE_8021Q = 0x8100;
    public static final int SLL_HEADER_BASE_SIZE = 10; // SLL stands for Linux cooked-mode capture
    public static final int SLL_ADDRESS_LENGTH_OFFSET = 4; // relative to SLL header
    public static final int IPV6_HEADER_SIZE = 40;
    public static final int IP_VHL_OFFSET = 0;	// relative to start of IP header
    public static final int IP_TTL_OFFSET = 8;	// relative to start of IP header
    public static final int IP_TOTAL_LEN_OFFSET = 2;	// relative to start of IP header
    public static final int IPV6_PAYLOAD_LEN_OFFSET = 4; // relative to start of IP header
    public static final int IPV6_HOPLIMIT_OFFSET = 7; // relative to start of IP header
    public static final int IP_PROTOCOL_OFFSET = 9;	// relative to start of IP header
    public static final int IPV6_NEXTHEADER_OFFSET = 6; // relative to start of IP header
    public static final int IP_SRC_OFFSET = 12;	// relative to start of IP header
    public static final int IPV6_SRC_OFFSET = 8; // relative to start of IP header
    public static final int IP_DST_OFFSET = 16;	// relative to start of IP header
    public static final int IPV6_DST_OFFSET = 24; // relative to start of IP header
    public static final int IP_ID_OFFSET = 4;	// relative to start of IP header
    public static final int IPV6_ID_OFFSET = 4;	// relative to start of IP header
    public static final int IP_FLAGS_OFFSET = 6;	// relative to start of IP header
    public static final int IPV6_FLAGS_OFFSET = 3;	// relative to start of IP header
    public static final int IP_FRAGMENT_OFFSET = 6;	// relative to start of IP header
    public static final int IPV6_FRAGMENT_OFFSET = 2;	// relative to start of IP header
    public static final int UDP_HEADER_SIZE = 8;
    public static final int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
    public static final int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;
    public static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
    public static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
    public static final int TCP_HEADER_DATA_OFFSET = 12;

    private static final int IP_V4 = 4;
    private static final int IP_V6 = 6;

    private static final String JSON_LAYERS = "layers";
    private static final String JSON_TIMESTAMP = "timestamp";
    private static final String JSON_FRAME = "frame";
    private static final String JSON_FRAME_NUMBER = "frame_frame_number";
    private static final String JSON_IP = "ip";
    private static final String JSON_IP_VERSION = "ip_ip_version";
    private static final String JSON_IP_SRC = "ip_ip_src";
    private static final String JSON_IP_DST = "ip_ip_dst";
    private static final String JSON_IP_HEADER_LEN = "ip_ip_hdr_len";
    private static final String JSON_IP_TTL = "ip_ip_ttl";
    private static final String JSON_IP_FLAG_DF = "ip_flags_ip_flags_df";
    private static final String JSON_IP_FLAG_MF = "ip_flags_ip_flags_mf";
    private static final String JSON_IP_FRAGMENT_OFFSET = "ip_ip_frag_offset";
    private static final String JSON_IP_ID = "ip_ip_id";
    private static final String JSON_IP_PROTOCOL = "ip_ip_proto";
    private static final String JSON_UDP = "udp";
    private static final String JSON_UDP_SRC_PORT = "udp_udp_srcport";
    private static final String JSON_UDP_DST_PORT = "udp_udp_dstport";
    private static final String JSON_UDP_CHECKSUM = "udp_udp_checksum";
    private static final String JSON_UDP_LEN = "udp_udp_length";
    private static final String JSON_TCP_SRC_PORT = "tcp_tcp_srcport";
    private static final String JSON_TCP_DST_PORT = "tcp_tcp_dstport";
    private static final String JSON_TCP = "tcp";
    private static final String JSON_TCP_HEADER_LEN = "tcp_tcp_hdr_len";
    private static final String JSON_TCP_SEQ = "tcp_tcp_seq";
    private static final String JSON_TCP_ACK = "tcp_tcp_ack";
    private static final String JSON_TCP_FLAG_NS = "tcp_flags_tcp_flags_ns";
    private static final String JSON_TCP_FLAG_CWR = "tcp_flags_tcp_flags_cwr";
    private static final String JSON_TCP_FLAG_ECE = "tcp_flags_tcp_flags_ecn";
    private static final String JSON_TCP_FLAG_URG = "tcp_flags_tcp_flags_urg";
    private static final String JSON_TCP_FLAG_ACK = "tcp_flags_tcp_flags_ack";
    private static final String JSON_TCP_FLAG_PSH = "tcp_flags_tcp_flags_push";
    private static final String JSON_TCP_FLAG_RST = "tcp_flags_tcp_flags_reset";
    private static final String JSON_TCP_FLAG_SYN = "tcp_flags_tcp_flags_syn";
    private static final String JSON_TCP_FLAG_FIN = "tcp_flags_tcp_flags_fin";
    private static final String JSON_TCP_PAYLOAD_LEN = "tcp_tcp_len";

    public String getFlowString() {
        return "[" +
                this.get(Packet.PROTOCOL) +
                "@" +
                this.get(Packet.SRC) +
                ":" +
                this.get(Packet.SRC_PORT) +
                "->" +
                this.get(Packet.DST) +
                ":" +
                this.get(Packet.DST_PORT) +
                "]";
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        for (Map.Entry<String, Object> entry : entrySet()) {
            sb.append(entry.getKey());
            sb.append('=');
            sb.append(entry.getValue());
            sb.append(',');
        }
        if (sb.length() > 0)
            return sb.substring(0, sb.length() - 1);
        return null;
    }

    public static String convertProtocolIdentifier(int identifier) {
        return protocols.get(identifier);
    }

    /**
     * Attempts to parse the input jsonFrame into Packet.
     * @param jsonFrame An input frame to be parsed.
     * @return A Packet object for the given input jsonFrame.
     */
    @SuppressWarnings("unchecked")
    public static JsonPacket parsePacket(String jsonFrame) {
        JsonPacket packet = new JsonPacket();
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            Map<String, Object> jsonMap = objectMapper.readValue(jsonFrame,
                    new TypeReference<Map<String,Object>>(){});
            addTimeStamp(packet, (String) jsonMap.get(JSON_TIMESTAMP));
            Map<String, Object> layers = (Map<String, Object>) jsonMap.get(JSON_LAYERS);
            if (layers == null) {
                return packet;
            }

            parseFrameLayer(packet, (Map<String, Object>) layers.get(JSON_FRAME));
            parseIpLayer(packet, (Map<String, Object>) layers.get(JSON_IP));
            if ((Boolean)packet.get(FRAGMENT)) {
                LOG.info("IP fragment detected - fragmented packets are not supported.");
            } else {
                parseTransportLayer(packet, layers);
            }

        } catch (IOException e) {
            LOG.error("Malformed JSON format of packet.");
        }

        return packet;
    }

    private static void addTimeStamp(JsonPacket packet, String timeStamp) {
        try {
            long unixTimeStamp = Long.decode(timeStamp);
            packet.put(TIMESTAMP, unixTimeStamp * TICKS_PER_MILLISECOND + UNIX_BASE_TICKS);
        } catch (NumberFormatException e) {
            LOG.warn("Unknown timestamp format.");
        }
    }

    private static void parseFrameLayer(JsonPacket packet, Map<String, Object> frame) {
        if (frame == null) {
            LOG.warn("Missing frame layer.");
            return;
        }
        addIntValue(packet, NUMBER, (String) frame.get(JSON_FRAME_NUMBER));
    }

    private static void parseIpLayer(JsonPacket packet, Map<String, Object> ipLayer) {
        if (ipLayer != null) {
            addIntValue(packet, IP_VERSION, (String) ipLayer.get(JSON_IP_VERSION));
            addIntValue(packet, IP_HEADER_LENGTH, (String) ipLayer.get(JSON_IP_HEADER_LEN));
            Integer ip_version = (Integer) packet.get(IP_VERSION);
            if (ip_version != null && ip_version == IP_V4) {
                parseIpV4(packet, ipLayer);
            } else if (ip_version != null && ip_version == IP_V6) {
                parseIpV6(packet, ipLayer);
            } else {
                LOG.warn("Missing IP version number.");
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void parseTransportLayer(JsonPacket packet, Map<String, Object> layers) {
        String protocol = (String)packet.get(Packet.PROTOCOL);
        switch (protocol) {
            case PROTOCOL_TCP:
                parseTcp(packet, (Map<String, Object>) layers.get(JSON_TCP));
                break;
            case PROTOCOL_UDP:
                parseUdp(packet, (Map<String, Object>) layers.get(JSON_UDP));
                break;
            default:
                LOG.info("Not supported transport layer protocol.");
                break;
        }
    }

    private static void parseUdp(JsonPacket packet, Map<String, Object> udp) {
        if (udp == null) {
            LOG.error("Missing UDP layer.");
            return;
        }
        addIntValue(packet, SRC_PORT, (String) udp.get(JSON_UDP_SRC_PORT));
        addIntValue(packet, DST_PORT, (String) udp.get(JSON_UDP_DST_PORT));
        addIntValue(packet, UDPSUM, (String) udp.get(JSON_UDP_CHECKSUM));
        if (packet.get(UDPSUM) != null) {
            if ((Integer)packet.get(UDPSUM) == 0) {
                packet.remove(UDPSUM);
            }
        }

        try {
            int udpLen = Integer.parseInt((String) udp.get(JSON_UDP_LEN));
            packet.put(UDP_LENGTH, udpLen - UDP_HEADER_SIZE);
            packet.put(PAYLOAD_LEN, udpLen - UDP_HEADER_SIZE);
            packet.put(LEN, udpLen - UDP_HEADER_SIZE);
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + PAYLOAD_LEN);
        }
    }

    private static void parseTcp(JsonPacket packet, Map<String, Object> tcp) {
        if (tcp == null) {
            LOG.error("Missing TCP layer.");
            return;
        }

        addIntValue(packet, SRC_PORT, (String) tcp.get(JSON_TCP_SRC_PORT));
        addIntValue(packet, DST_PORT, (String) tcp.get(JSON_TCP_DST_PORT));

        addIntValue(packet, TCP_HEADER_LENGTH, (String) tcp.get(JSON_TCP_HEADER_LEN));
        addIntValue(packet, TCP_SEQ, (String) tcp.get(JSON_TCP_SEQ));
        addIntValue(packet, TCP_ACK, (String) tcp.get(JSON_TCP_ACK));
        String payload_len = (String) tcp.get(JSON_TCP_PAYLOAD_LEN);
        addIntValue(packet, PAYLOAD_LEN, payload_len);
        addIntValue(packet, LEN, payload_len);

        addBoolValue(packet, TCP_FLAG_NS, (String) tcp.get(JSON_TCP_FLAG_NS));
        addBoolValue(packet, TCP_FLAG_CWR, (String) tcp.get(JSON_TCP_FLAG_CWR));
        addBoolValue(packet, TCP_FLAG_ECE, (String) tcp.get(JSON_TCP_FLAG_ECE));
        addBoolValue(packet, TCP_FLAG_URG, (String) tcp.get(JSON_TCP_FLAG_URG));
        addBoolValue(packet, TCP_FLAG_ACK, (String) tcp.get(JSON_TCP_FLAG_ACK));
        addBoolValue(packet, TCP_FLAG_PSH, (String) tcp.get(JSON_TCP_FLAG_PSH));
        addBoolValue(packet, TCP_FLAG_RST, (String) tcp.get(JSON_TCP_FLAG_RST));
        addBoolValue(packet, TCP_FLAG_SYN, (String) tcp.get(JSON_TCP_FLAG_SYN));
        addBoolValue(packet, TCP_FLAG_FIN, (String) tcp.get(JSON_TCP_FLAG_FIN));
    }


    private static void parseIpV4(JsonPacket packet, Map<String, Object> ipV4) {
        addStringValue(packet, SRC, (String) ipV4.get(JSON_IP_SRC));
        addStringValue(packet, DST, (String) ipV4.get(JSON_IP_DST));
        addIntValue(packet, TTL, (String) ipV4.get(JSON_IP_TTL));

        addIntValue(packet, IP_FLAGS_DF, (String) ipV4.get(JSON_IP_FLAG_DF));
        addIntValue(packet, IP_FLAGS_MF, (String) ipV4.get(JSON_IP_FLAG_MF));
        addIntValue(packet, FRAGMENT_OFFSET, (String) ipV4.get(JSON_IP_FRAGMENT_OFFSET));

        Integer flagMf = (Integer) packet.get(IP_FLAGS_MF);
        Integer fragOffset = (Integer) packet.get(FRAGMENT_OFFSET);
        if (flagMf != null && fragOffset != null) {
            if (flagMf != 0 || fragOffset != 0) {
                packet.put(FRAGMENT, true);
                packet.put(LAST_FRAGMENT, (flagMf == 0));
            } else {
                packet.put(FRAGMENT, false);
            }
        }

        addLongValue(packet, ID, (String) ipV4.get(JSON_IP_ID));

        try {
            Integer iProtocol = Integer.parseInt((String) ipV4.get(JSON_IP_PROTOCOL));
            String sProtocol = convertProtocolIdentifier(iProtocol);
            addStringValue(packet, PROTOCOL, sProtocol);
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + PROTOCOL);
        }
    }

    private static void parseIpV6(JsonPacket packet, Map<String, Object> ipV6) {
        // TODO parse ipv6
    }

    private static void addBoolValue(JsonPacket packet, String key, String value) {
        if (value == null) {
            LOG.warn("Missing value - " + key);
            return;
        }
        if ("0".equals(value)) {
            packet.put(key, false);
        } else if ("1".equals(value)) {
            packet.put(key, true);
        } else {
            LOG.warn("Invalid value - " + key);
        }
    }

    private static void addStringValue(JsonPacket packet, String key, String value) {
        if (value != null) {
            packet.put(key, value);
            return;
        }
        LOG.warn("Missing value - " + key);
    }

    private static void addLongValue(JsonPacket packet, String key, String value) {
        try {
            packet.put(key, Long.decode(value));
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + key);
        }
    }

    private static void addIntValue(JsonPacket packet, String key, String value) {
        try {
            packet.put(key, Integer.decode(value));
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + key);
        }
    }

}
