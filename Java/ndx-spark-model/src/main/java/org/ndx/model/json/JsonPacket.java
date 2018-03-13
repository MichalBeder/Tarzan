package org.ndx.model.json;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import net.sf.json.JSONObject;
import org.ndx.model.Packet;
import org.ndx.model.parsers.applayer.AppLayerParser;
import org.ndx.model.parsers.applayer.DnsParser;

public class JsonPacket extends Packet {
//    protected static final long serialVersionUID = 8723206921174160147L;

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

    /**
     * Attempts to parse the input jsonFrame into Packet.
     * @param jsonFrame An input frame to be parsed.
     */
    @Override
    @SuppressWarnings("unchecked")
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
            parseIpLayer((Map<String, Object>) layers.get(JSON_IP));
            if ((Boolean) get(FRAGMENT)) {
                LOG.info("IP fragment detected - fragmented packets are not supported.");
            } else {
                parseTransportLayer(layers);
                parseApplicationLayer(layers);
            }
        } catch (IOException e) {
            LOG.error("Malformed JSON format of packet.");
        }
    }

    private void parseFrameLayer(Map<String, Object> frame) {
        if (frame == null) {
            LOG.warn("Missing frame layer.");
            return;
        }
        JsonHelper.addIntValue(this, NUMBER, (String) frame.get(JSON_FRAME_NUMBER));
    }

    private void parseIpLayer(Map<String, Object> ipLayer) {
        if (ipLayer != null) {
            JsonHelper.addIntValue(this, IP_VERSION, (String) ipLayer.get(JSON_IP_VERSION));
            JsonHelper.addIntValue(this, IP_HEADER_LENGTH, (String) ipLayer.get(JSON_IP_HEADER_LEN));
            Integer ip_version = (Integer) get(IP_VERSION);
            if (ip_version != null && ip_version == IP_V4) {
                parseIpV4(ipLayer);
            } else if (ip_version != null && ip_version == IP_V6) {
                parseIpV6(ipLayer);
            } else {
                LOG.warn("Missing IP version number.");
            }
        }
    }

    @SuppressWarnings("unchecked")
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
                LOG.info("Not supported transport layer protocol.");
                break;
        }
    }

    private void parseApplicationLayer(Map<String, Object> layers) {
        Map<String, Object> payload = detectProtocol(layers);
        ApplicationLayerProtocols appProtocol = (ApplicationLayerProtocols) get(APP_LAYER_PROTOCOL);
        AppLayerParser parser = null;
        switch (appProtocol) {
            case DNS: parser = new DnsParser(); break;
            case HTTP: break;
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
            parser.parse(payload);
            this.putAll(parser);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String,Object> detectProtocol(Map<String, Object> layers) {
        Map<String, Object> appPayload = null;
        ApplicationLayerProtocols appProtocol = ApplicationLayerProtocols.NOT_SUPPORTED;
        for (ApplicationLayerProtocols protocol : ApplicationLayerProtocols.values()) {
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
            LOG.error("Missing UDP layer.");
            return;
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
            LOG.error("Missing TCP layer.");
            return;
        }

        JsonHelper.addIntValue(this, SRC_PORT, (String) tcp.get(JSON_TCP_SRC_PORT));
        JsonHelper.addIntValue(this, DST_PORT, (String) tcp.get(JSON_TCP_DST_PORT));

        JsonHelper.addIntValue(this, TCP_HEADER_LENGTH, (String) tcp.get(JSON_TCP_HEADER_LEN));
        JsonHelper.addIntValue(this, TCP_SEQ, (String) tcp.get(JSON_TCP_SEQ));
        JsonHelper.addIntValue(this, TCP_ACK, (String) tcp.get(JSON_TCP_ACK));
        String payload_len = (String) tcp.get(JSON_TCP_PAYLOAD_LEN);
        JsonHelper.addIntValue(this, PAYLOAD_LEN, payload_len);
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
        JsonHelper.addStringValue(this, SRC, (String) ipV4.get(JSON_IP_SRC));
        JsonHelper.addStringValue(this, DST, (String) ipV4.get(JSON_IP_DST));
        JsonHelper.addIntValue(this, TTL, (String) ipV4.get(JSON_IP_TTL));

        JsonHelper.addIntValue(this, IP_FLAGS_DF, (String) ipV4.get(JSON_IP_FLAG_DF));
        JsonHelper.addIntValue(this, IP_FLAGS_MF, (String) ipV4.get(JSON_IP_FLAG_MF));
        JsonHelper.addIntValue(this, FRAGMENT_OFFSET, (String) ipV4.get(JSON_IP_FRAGMENT_OFFSET));

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

        JsonHelper.addLongValue(this, ID, (String) ipV4.get(JSON_IP_ID));

        try {
            Integer iProtocol = Integer.parseInt((String) ipV4.get(JSON_IP_PROTOCOL));
            String sProtocol = convertProtocolIdentifier(iProtocol);
            JsonHelper.addStringValue(this, PROTOCOL, sProtocol);
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + PROTOCOL);
        }
    }

    private void parseIpV6(Map<String, Object> ipV6) {
        // TODO parse ipv6
    }

}
