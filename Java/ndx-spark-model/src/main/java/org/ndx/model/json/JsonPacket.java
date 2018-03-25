package org.ndx.model.json;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;
import java.util.stream.Stream;

import com.fasterxml.jackson.core.type.TypeReference;
import net.sf.json.JSONObject;
import org.apache.commons.lang.NotImplementedException;
import org.ndx.model.Packet;
import org.ndx.model.parsers.applayer.AppLayerParser;
import org.ndx.model.parsers.applayer.DnsJsonParser;
import org.ndx.model.parsers.applayer.HttpJsonParser;
import org.ndx.model.parsers.applayer.SslJsonParser;

public class JsonPacket extends Packet {

    private static final String JSON_LAYERS = "layers";
    private static final String JSON_TIMESTAMP = "timestamp";
    private static final String JSON_FRAME = "frame";
    private static final String JSON_FRAME_NUMBER = "frame_frame_number";
    private static final String JSON_FRAME_LENGTH = "frame_frame_len";

    private static final String JSON_IPV4 = "ip";
    private static final String JSON_IPV4_SRC = "ip_ip_src";
    private static final String JSON_IPV4_DST = "ip_ip_dst";
    private static final String JSON_IPV4_HEADER_LEN = "ip_ip_hdr_len";
    private static final String JSON_IPV4_TTL = "ip_ip_ttl";
    private static final String JSON_IPV4_FLAG_DF = "ip_flags_ip_flags_df";
    private static final String JSON_IPV4_FLAG_MF = "ip_flags_ip_flags_mf";
    private static final String JSON_IPV4_FRAGMENT_OFFSET = "ip_ip_frag_offset";
    private static final String JSON_IPV4_ID = "ip_ip_id";
    private static final String JSON_IPV4_PROTOCOL = "ip_ip_proto";
    private static final String JSON_IPV6 = "ipv6";
    private static final String JSON_IPV6_SRC = "ipv6_ipv6_src";
    private static final String JSON_IPV6_DST = "ipv6_ipv6_dst";
    private static final String JSON_IPV6_NEXT = "ipv6_ipv6_nxt";
    private static final String JSON_IPV6_NEXT_SUFFIX = "_nxt";
    private static final String JSON_IPV6_HOP_LIMIT = "ipv6_ipv6_hlim";
    private static final String JSON_IPV6_FRAGMENT_HEADER = "ipv6_ipv6_fraghdr";

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
    private static final String JSON_TCP_PAYLOAD = "tcp_tcp_payload";
    private static final String JSON_TCP_PAYLOAD_LEN = "tcp_tcp_len";

    private static final int IPV4 = 4;
    private static final int IPV6 = 6;

    /**
     * Attempts to parse the input jsonFrame into Packet.
     * @param jsonFrame An input frame to be parsed.
     */
    @Override
    public void parsePacket(String jsonFrame) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            JSONObject jsonObject = JSONObject.fromObject(jsonFrame);
            Map<String, Object> jsonMap = objectMapper.readValue(jsonObject.toString(),
                    new TypeReference<Map<String,Object>>(){});
            put(TIMESTAMP, JsonHelper.getLongValue(TIMESTAMP, jsonMap.get(JSON_TIMESTAMP)));
            Map<String, Object> layers = JsonHelper.castHashMap(jsonMap, JSON_LAYERS);
            if (layers == null) {
                return;
            }

            parseFrameLayer(JsonHelper.castHashMap(layers, JSON_FRAME));
            parseIpLayer(layers);
            if ((boolean) get(FRAGMENT)) {
                LOG.info("IP fragment detected - fragmented packets are not supported.");
            } else {
                parseTransportLayer(layers);
                parseApplicationLayer(layers);
            }
        } catch (IOException e) {
            LOG.warn("Malformed JSON packet.");
        } catch (IllegalArgumentException e) {
            LOG.warn(e.getMessage());
        } catch (NotImplementedException e) {
            LOG.info(e.getMessage());
        }
    }

    private void parseFrameLayer(Map<String, Object> frame) {
        if (frame == null) {
            throw new IllegalArgumentException("Missing frame layer.");
        }
        put(NUMBER, JsonHelper.getIntValue(NUMBER, frame.get(JSON_FRAME_NUMBER)));
        put(FRAME_LENGTH, JsonHelper.getIntValue(FRAME_LENGTH, frame.get(JSON_FRAME_LENGTH)));
    }

    private void parseIpLayer(Map<String, Object> layers) {
        if (layers == null) {
            throw new IllegalArgumentException("Malformed JSON packet.");
        }
        if (layers.containsKey(JSON_IPV4)) {
            parseIpV4(JsonHelper.castHashMap(layers, JSON_IPV4));
        } else if (layers.containsKey(JSON_IPV6)) {
            parseIpV6(JsonHelper.castHashMap(layers, JSON_IPV6));
        } else {
            throw new NotImplementedException("Not supported network layer protocol.");
        }
    }

    private void parseTransportLayer(Map<String, Object> layers) {
        if (layers.containsKey(PROTOCOL_TCP.toLowerCase())) {
            parseTcp(JsonHelper.castHashMap(layers, JSON_TCP));
            put(PROTOCOL, PROTOCOL_TCP);
        } else if (layers.containsKey(PROTOCOL_UDP.toLowerCase())) {
            parseUdp(JsonHelper.castHashMap(layers, JSON_UDP));
            put(PROTOCOL, PROTOCOL_UDP);
        } else {
            if (layers.containsKey(PROTOCOL_ICMP.toLowerCase())) {
                put(PROTOCOL, PROTOCOL_ICMP);
            }
            throw new NotImplementedException("Not supported transport layer protocol.");
        }
    }

    private void parseApplicationLayer(Map<String, Object> layers) {
        AppLayerProtocols appProtocol = detectAppProtocol(layers);
        put(APP_LAYER_PROTOCOL, appProtocol);
        if (appProtocol == AppLayerProtocols.UNKNOWN) return;
        Map<String,Object> payload = JsonHelper.castHashMap(layers, appProtocol.name().toLowerCase());

        if (payload != null) {
            parseAppProtocols(appProtocol, payload);
        }
    }

    private void parseAppProtocols(AppLayerProtocols protocol, Map<String, Object> payload) {
        AppLayerParser parser = null;
        switch (protocol) {
            case DNS:
                DnsJsonParser dnsParser = new DnsJsonParser();
                dnsParser.parse(payload);
                parser = dnsParser;
                break;
            case HTTP:
                HttpJsonParser httpParser = new HttpJsonParser();
                try {
                    httpParser.parse(payload);
                    parser = httpParser;
                } catch (IllegalArgumentException e) {
                    put(APP_LAYER_PROTOCOL, AppLayerProtocols.UNKNOWN);
                }
                break;
            case SSL:
                SslJsonParser sslParser = new SslJsonParser();
                sslParser.parse(payload);
                parser = sslParser;
                break;
            case SMTP:
            case POP3:
            case IMAP: break;
            default:
                LOG.info("Not supported application layer protocol.");
                break;
        }

        if (parser != null) {
            this.putAll(parser);
        }
    }

    private AppLayerProtocols detectAppProtocol(Map<String, Object> layers) {
        return Stream.of(AppLayerProtocols.values())
                .filter(x -> x != AppLayerProtocols.UNKNOWN)
                .filter(x -> layers.keySet().contains(x.name().toLowerCase()))
                .findFirst()
                .orElse(AppLayerProtocols.UNKNOWN);

//        for (AppLayerProtocols protocol : AppLayerProtocols.values()) {
//            if (protocol == AppLayerProtocols.UNKNOWN) continue;
//            if (layers.keySet().contains(protocol.name().toLowerCase())) {
//                appProtocol = protocol;
//                break;
//            }
//        }
//        if (appProtocol == AppLayerProtocols.UNKNOWN) { // detect https
//            Integer srcPort = (Integer)get(SRC_PORT);
//            Integer dstPort = (Integer)get(DST_PORT);
//            if (srcPort != null && dstPort != null && (srcPort == 443 || dstPort == 443)) {
//                appProtocol = AppLayerProtocols.HTTPS;
//            }
//        }

//        return appProtocol;
    }

    private void parseUdp(Map<String, Object> udp) {
        if (udp == null) {
            throw new IllegalArgumentException("Missing UDP layer.");
        }
        put(SRC_PORT, JsonHelper.getIntValue(SRC_PORT, udp.get(JSON_UDP_SRC_PORT)));
        put(DST_PORT, JsonHelper.getIntValue(DST_PORT, udp.get(JSON_UDP_DST_PORT)));
        put(UDPSUM, JsonHelper.getIntValue(UDPSUM, udp.get(JSON_UDP_CHECKSUM)));
        if ((Integer) get(UDPSUM) == 0) {
            remove(UDPSUM);
        }

        try {
            int udpLen = Integer.parseInt((String) udp.get(JSON_UDP_LEN));
            put(UDP_LENGTH, udpLen - UDP_HEADER_SIZE);
            put(PAYLOAD_LEN, udpLen - UDP_HEADER_SIZE);
            put(LEN, udpLen - UDP_HEADER_SIZE);
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + PAYLOAD_LEN);
        }
    }

    private void parseTcp(Map<String, Object> tcp) {
        if (tcp == null) {
            throw new IllegalArgumentException("Missing TCP layer.");
        }
        put(SRC_PORT, JsonHelper.getIntValue(SRC_PORT, tcp.get(JSON_TCP_SRC_PORT)));
        put(DST_PORT, JsonHelper.getIntValue(DST_PORT, tcp.get(JSON_TCP_DST_PORT)));

        put(TCP_HEADER_LENGTH, JsonHelper.getIntValue(TCP_HEADER_LENGTH, tcp.get(JSON_TCP_HEADER_LEN)));
        put(TCP_SEQ, JsonHelper.getIntValue(TCP_SEQ, tcp.get(JSON_TCP_SEQ)));
        put(TCP_ACK, JsonHelper.getIntValue(TCP_ACK, tcp.get(JSON_TCP_ACK)));
        Object payload_len = tcp.get(JSON_TCP_PAYLOAD_LEN);
        put(PAYLOAD_LEN, JsonHelper.getIntValue(PAYLOAD_LEN, payload_len));
        String payload = JsonHelper.castString(tcp, JSON_TCP_PAYLOAD);
        put(HEX_PAYLOAD, payload.replace(":", ""));
        put(LEN, JsonHelper.getIntValue(LEN, payload_len));

        put(TCP_FLAG_NS, JsonHelper.getBoolValue(TCP_FLAG_NS, tcp.get(JSON_TCP_FLAG_NS), false));
        put(TCP_FLAG_CWR, JsonHelper.getBoolValue(TCP_FLAG_CWR, tcp.get(JSON_TCP_FLAG_CWR), false));
        put(TCP_FLAG_ECE, JsonHelper.getBoolValue(TCP_FLAG_ECE, tcp.get(JSON_TCP_FLAG_ECE), false));
        put(TCP_FLAG_URG, JsonHelper.getBoolValue(TCP_FLAG_URG, tcp.get(JSON_TCP_FLAG_URG), false));
        put(TCP_FLAG_ACK, JsonHelper.getBoolValue(TCP_FLAG_ACK, tcp.get(JSON_TCP_FLAG_ACK), false));
        put(TCP_FLAG_PSH, JsonHelper.getBoolValue(TCP_FLAG_PSH, tcp.get(JSON_TCP_FLAG_PSH), false));
        put(TCP_FLAG_RST, JsonHelper.getBoolValue(TCP_FLAG_RST, tcp.get(JSON_TCP_FLAG_RST), false));
        put(TCP_FLAG_SYN, JsonHelper.getBoolValue(TCP_FLAG_SYN, tcp.get(JSON_TCP_FLAG_SYN), false));
        put(TCP_FLAG_FIN, JsonHelper.getBoolValue(TCP_FLAG_FIN, tcp.get(JSON_TCP_FLAG_FIN), false));
    }

    private void parseIpV4(Map<String, Object> ipV4) {
        if (ipV4 == null) {
            throw new IllegalArgumentException("Missing ipv4 layer.");
        }
        put(IP_VERSION, IPV4);
        put(IP_HEADER_LENGTH, JsonHelper.getIntValue(IP_HEADER_LENGTH, ipV4.get(JSON_IPV4_HEADER_LEN)));
        put(SRC, JsonHelper.getStringValue(SRC, ipV4.get(JSON_IPV4_SRC)));
        put(DST, JsonHelper.getStringValue(DST, ipV4.get(JSON_IPV4_DST)));
        put(TTL, JsonHelper.getIntValue(TTL, ipV4.get(JSON_IPV4_TTL)));

        put(IP_FLAGS_DF, JsonHelper.getIntValue(IP_FLAGS_DF, ipV4.get(JSON_IPV4_FLAG_DF)));
        put(IP_FLAGS_MF, JsonHelper.getIntValue(IP_FLAGS_MF, ipV4.get(JSON_IPV4_FLAG_MF)));
        put(FRAGMENT_OFFSET, JsonHelper.getIntValue(FRAGMENT_OFFSET, ipV4.get(JSON_IPV4_FRAGMENT_OFFSET)));

        int flagMf = (int) get(IP_FLAGS_MF);
        int fragOffset = (int) get(FRAGMENT_OFFSET);
        if (flagMf > 0 || fragOffset > 0) {
            put(FRAGMENT, true);
            put(LAST_FRAGMENT, (flagMf == 0));
        } else {
            put(FRAGMENT, false);
        }

        put(ID, JsonHelper.getLongValue(ID, ipV4.get(JSON_IPV4_ID)));

        try {
            Integer protocol = Integer.parseInt((String) ipV4.get(JSON_IPV4_PROTOCOL));
            put(PROTOCOL, JsonHelper.getStringValue(PROTOCOL, convertProtocolIdentifier(protocol)));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Missing transport layer protocol from ipv4 header.");
        }
    }

    private void parseIpV6(Map<String, Object> ipV6) {
        if (ipV6 == null) {
            throw new IllegalArgumentException("Missing ipv6 layer.");
        }
        put(IP_VERSION, IPV6);
        put(SRC, JsonHelper.getStringValue(SRC, ipV6.get(JSON_IPV6_SRC)));
        put(DST, JsonHelper.getStringValue(DST, ipV6.get(JSON_IPV6_DST)));
        put(TTL, JsonHelper.getIntValue(TTL, ipV6.get(JSON_IPV6_HOP_LIMIT)));

        if (ipV6.containsKey(JSON_IPV6_FRAGMENT_HEADER)) {
            put(FRAGMENT, true);
        } else {
            put(FRAGMENT, false);
            put(PROTOCOL, PROTOCOL_FRAGMENT);
        }
    }

}
