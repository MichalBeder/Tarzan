package org.ndx.model.json;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import net.sf.json.JSONObject;
import org.apache.commons.lang.NotImplementedException;
import org.ndx.model.Packet;
import org.ndx.model.parsers.applayer.AppLayerParser;
import org.ndx.model.parsers.applayer.DnsJsonParser;
import org.ndx.model.parsers.applayer.HttpJsonParser;

@SuppressWarnings("unchecked")
public class JsonPacket extends Packet {

    private static final String JSON_LAYERS = "layers";
    private static final String JSON_TIMESTAMP = "timestamp";
    private static final String JSON_FRAME = "frame";
    private static final String JSON_FRAME_NUMBER = "frame_frame_number";

    private static final String JSON_IP_VERSION = "ip_ip_version";
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

    private static final String IPV4 = "4";
    private static final String IPV6 = "6";

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
            JsonHelper.addLongValue(this, TIMESTAMP, (String) jsonMap.get(JSON_TIMESTAMP));
            Map<String, Object> layers = (Map<String, Object>) jsonMap.get(JSON_LAYERS);
            if (layers == null) {
                return;
            }

            parseFrameLayer((Map<String, Object>) layers.get(JSON_FRAME));
            parseIpLayer(layers);
            if ((Boolean) get(FRAGMENT)) {
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
        JsonHelper.addIntValue(this, NUMBER, (String) frame.get(JSON_FRAME_NUMBER));
    }

    private void parseIpLayer(Map<String, Object> layers) {
        if (layers == null) {
            throw new IllegalArgumentException("Malformed JSON packet.");
        }
        Object ip = layers.get(JSON_IPV4);
        boolean implemented = false;
        if (ip != null) {
            parseIpV4((Map<String, Object>) ip);
            implemented = true;
        }
        ip = layers.get(JSON_IPV6);
        if (ip != null) {
            parseIpV6((Map<String, Object>)ip);
            implemented = true;
        }
        if (!implemented) {
            throw new NotImplementedException("Not supported network layer protocol.");
        }
    }

    private void parseTransportLayer(Map<String, Object> layers) {
        String protocol = (String) get(PROTOCOL);
        switch (protocol) {
            case PROTOCOL_TCP:
                parseTcp((Map<String, Object>) layers.get(JSON_TCP));
                break;
            case PROTOCOL_UDP:
                parseUdp((Map<String, Object>) layers.get(JSON_UDP));
                break;
            default:
                throw new NotImplementedException("Not supported transport layer protocol.");
        }
    }

    private void parseApplicationLayer(Map<String, Object> layers) {
        Map<String, Object> payload = detectProtocol(layers);
        AppLayerProtocols appProtocol = (AppLayerProtocols) get(APP_LAYER_PROTOCOL);
        AppLayerParser parser = null;
        switch (appProtocol) {
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
                } catch (IllegalAccessException e) {
                    put(APP_LAYER_PROTOCOL, AppLayerProtocols.NOT_SUPPORTED);
                }
                break;
            case HTTPS: break;
            case SMTP: break;
            case POP3: break;
            case IMAP: break;
            case TLS: break;
            default:
                LOG.info("Not supported application layer protocol.");
                break;
        }
        if (parser != null) {
            this.putAll(parser);
        }
    }

    private Map<String,Object> detectProtocol(Map<String, Object> layers) {
        Map<String, Object> appPayload = null;
        AppLayerProtocols appProtocol = AppLayerProtocols.NOT_SUPPORTED;
        for (AppLayerProtocols protocol : AppLayerProtocols.values()) {
            appPayload = (Map<String, Object>) layers.get(protocol.name().toLowerCase());
            if (appPayload != null) {
                appProtocol = protocol;
                break;
            }
        }
        put(APP_LAYER_PROTOCOL, appProtocol);
        return appPayload;
    }

    private void parseUdp(Map<String, Object> udp) {
        if (udp == null) {
            throw new IllegalArgumentException("Missing UDP layer.");
        }
        JsonHelper.addIntValue(this, SRC_PORT, (String) udp.get(JSON_UDP_SRC_PORT));
        JsonHelper.addIntValue(this, DST_PORT, (String) udp.get(JSON_UDP_DST_PORT));
        JsonHelper.addIntValue(this, UDPSUM, (String) udp.get(JSON_UDP_CHECKSUM));
        if (get(UDPSUM) != null) {
            if ((Integer) get(UDPSUM) == 0) {
                remove(UDPSUM);
            }
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

        JsonHelper.addIntValue(this, SRC_PORT, (String) tcp.get(JSON_TCP_SRC_PORT));
        JsonHelper.addIntValue(this, DST_PORT, (String) tcp.get(JSON_TCP_DST_PORT));

        JsonHelper.addIntValue(this, TCP_HEADER_LENGTH, (String) tcp.get(JSON_TCP_HEADER_LEN));
        JsonHelper.addIntValue(this, TCP_SEQ, (String) tcp.get(JSON_TCP_SEQ));
        JsonHelper.addIntValue(this, TCP_ACK, (String) tcp.get(JSON_TCP_ACK));
        String payload_len = (String) tcp.get(JSON_TCP_PAYLOAD_LEN);
        JsonHelper.addIntValue(this, PAYLOAD_LEN, payload_len);
        String payload = tcp.get(JSON_TCP_PAYLOAD) != null ? (String) tcp.get(JSON_TCP_PAYLOAD) : "";
        JsonHelper.addStringValue(this, TCP_PAYLOAD, payload.replace(":", ""));
        JsonHelper.addIntValue(this, LEN, payload_len);

        JsonHelper.addBoolValue(this, TCP_FLAG_NS, (String) tcp.get(JSON_TCP_FLAG_NS));
        JsonHelper.addBoolValue(this, TCP_FLAG_CWR, (String) tcp.get(JSON_TCP_FLAG_CWR));
        JsonHelper.addBoolValue(this, TCP_FLAG_ECE, (String) tcp.get(JSON_TCP_FLAG_ECE));
        JsonHelper.addBoolValue(this, TCP_FLAG_URG, (String) tcp.get(JSON_TCP_FLAG_URG));
        JsonHelper.addBoolValue(this, TCP_FLAG_ACK, (String) tcp.get(JSON_TCP_FLAG_ACK));
        JsonHelper.addBoolValue(this, TCP_FLAG_PSH, (String) tcp.get(JSON_TCP_FLAG_PSH));
        JsonHelper.addBoolValue(this, TCP_FLAG_RST, (String) tcp.get(JSON_TCP_FLAG_RST));
        JsonHelper.addBoolValue(this, TCP_FLAG_SYN, (String) tcp.get(JSON_TCP_FLAG_SYN));
        JsonHelper.addBoolValue(this, TCP_FLAG_FIN, (String) tcp.get(JSON_TCP_FLAG_FIN));
    }

    private void parseIpV4(Map<String, Object> ipV4) {
        JsonHelper.addIntValue(this, IP_VERSION, IPV4);
        JsonHelper.addIntValue(this, IP_HEADER_LENGTH, (String) ipV4.get(JSON_IPV4_HEADER_LEN));
        JsonHelper.addStringValue(this, SRC, (String) ipV4.get(JSON_IPV4_SRC));
        JsonHelper.addStringValue(this, DST, (String) ipV4.get(JSON_IPV4_DST));
        JsonHelper.addIntValue(this, TTL, (String) ipV4.get(JSON_IPV4_TTL));

        JsonHelper.addIntValue(this, IP_FLAGS_DF, (String) ipV4.get(JSON_IPV4_FLAG_DF));
        JsonHelper.addIntValue(this, IP_FLAGS_MF, (String) ipV4.get(JSON_IPV4_FLAG_MF));
        JsonHelper.addIntValue(this, FRAGMENT_OFFSET, (String) ipV4.get(JSON_IPV4_FRAGMENT_OFFSET));

        Integer flagMf = (Integer) get(IP_FLAGS_MF);
        Integer fragOffset = (Integer) get(FRAGMENT_OFFSET);
        if (flagMf != null && fragOffset != null) {
            if (flagMf != 0 || fragOffset != 0) {
                put(FRAGMENT, true);
                put(LAST_FRAGMENT, (flagMf == 0));
            } else {
                put(FRAGMENT, false);
            }
        }

        JsonHelper.addLongValue(this, ID, (String) ipV4.get(JSON_IPV4_ID));

        try {
            Integer protocol = Integer.parseInt((String) ipV4.get(JSON_IPV4_PROTOCOL));
            JsonHelper.addStringValue(this, PROTOCOL, convertProtocolIdentifier(protocol));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Missing transport layer protocol from ipv4 header.");
        }
    }

    private void parseIpV6(Map<String, Object> ipV6) {
        JsonHelper.addIntValue(this, IP_VERSION, IPV6);
        JsonHelper.addStringValue(this, SRC, (String) ipV6.get(JSON_IPV6_SRC));
        JsonHelper.addStringValue(this, DST, (String) ipV6.get(JSON_IPV6_DST));
        JsonHelper.addIntValue(this, TTL, (String) ipV6.get(JSON_IPV6_HOP_LIMIT));
        put(FRAGMENT, false);
        addIpv6HeaderInfo((String) ipV6.get(JSON_IPV6_NEXT));
        String protocol = (String) get(PROTOCOL);
        if (protocol == null || protocol.equals(PROTOCOL_FRAGMENT)) { // extension headers
            ipV6.entrySet()
                .stream()
                .filter(e -> e.getValue() instanceof HashMap)
                .forEach(e -> {
                    Map<String, Object> map = (Map<String, Object>) e.getValue();
                    map.entrySet()
                            .stream()
                            .filter(entry -> entry.getKey().endsWith(JSON_IPV6_NEXT_SUFFIX))
                            .forEach(entry -> addIpv6HeaderInfo((String) entry.getValue()));
                });
        }
    }

    private void addIpv6HeaderInfo(String headerId) {
        if (headerId == null) return;
        try {
            int prot = Integer.parseInt(headerId);
            String protocol = convertProtocolIdentifier(prot);
            if (protocol != null) {
                JsonHelper.addStringValue(this, PROTOCOL, protocol);
            }
            if (prot == IPV6_FRAGMENT_CODE) {
                put(FRAGMENT, true);
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Malformed ipv6 header.");
        }
    }

}
