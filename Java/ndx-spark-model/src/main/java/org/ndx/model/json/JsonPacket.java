package org.ndx.model.json;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.stream.Stream;

import org.apache.commons.lang.NotImplementedException;
import org.ndx.model.Packet;
import org.ndx.model.parsers.applayer.*;

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
        try {
            JsonAdapter json = new JsonSfParser(jsonFrame);
            JsonAdapter layers = json.getLayer(JSON_LAYERS);
            parseFrameLayer(layers.getLayer(JSON_FRAME));
            JsonHelper.addValue((Integer) get(NUMBER), this, TIMESTAMP, json, JSON_TIMESTAMP,
                    JsonHelper.ValueTypes.LONG);
            parseIpLayer(layers);
            if ((boolean) get(FRAGMENT)) {
                LOG.info(getLogPrefix((Integer) get(NUMBER)) +
                        "IP fragment detected - fragmented packets are not supported.");
            } else {
                parseTransportLayer(layers);
                parseApplicationLayer(layers);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn(getLogPrefix((Integer) get(NUMBER)) + e.getMessage());
        } catch (NotImplementedException e) {
            LOG.info(getLogPrefix((Integer) get(NUMBER)) + e.getMessage());
        }
    }

    private void parseFrameLayer(JsonAdapter frame) {
        JsonHelper.addValue(0, this, NUMBER, frame, JSON_FRAME_NUMBER, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue((Integer) get(NUMBER), this, FRAME_LENGTH, frame, JSON_FRAME_LENGTH,
                JsonHelper.ValueTypes.INT);
    }

    private void parseIpLayer(JsonAdapter layers) {
        if (layers.containsKey(JSON_IPV4)) {
            parseIpV4(layers.getLayer(JSON_IPV4));
        } else if (layers.containsKey(JSON_IPV6)) {
            parseIpV6(layers.getLayer(JSON_IPV6));
        } else {
            throw new NotImplementedException("Not supported network layer protocol.");
        }
    }

    private void parseTransportLayer(JsonAdapter layers) {
        if (layers.containsKey(PROTOCOL_TCP.toLowerCase())) {
            parseTcp(layers.getLayer(JSON_TCP));
            put(PROTOCOL, PROTOCOL_TCP);
        } else if (layers.containsKey(PROTOCOL_UDP.toLowerCase())) {
            parseUdp(layers.getLayer(JSON_UDP));
            put(PROTOCOL, PROTOCOL_UDP);
        } else {
            if (layers.containsKey(PROTOCOL_ICMP.toLowerCase())) {
                put(PROTOCOL, PROTOCOL_ICMP);
            }
            throw new NotImplementedException("Not supported transport layer protocol.");
        }
    }

    private void parseApplicationLayer(JsonAdapter layers) {
        AppLayerProtocols appProtocol = detectAppProtocol(layers);
        put(APP_LAYER_PROTOCOL, appProtocol);
        if (appProtocol == AppLayerProtocols.UNKNOWN) return;

        AppLayerParser parser = null;
        Integer number = (Integer)get(NUMBER);
        if (number == null) number = 0;
        String protocol = appProtocol.name().toLowerCase();

        switch (appProtocol) {
            case DNS:
                DnsJsonParser dnsParser = new DnsJsonParser(number);
                dnsParser.parse(layers.getLayer(protocol));
                parser = dnsParser;
                break;
            case HTTP:
                HttpJsonParser httpParser = new HttpJsonParser(number);
                httpParser.parse(layers.getLayer(protocol));
                parser = httpParser;
                break;
            case SSL:
                ProtocolsOverSsl sslProtocol =
                        SslHelper.detectSslProtocol((Integer) get(SRC_PORT), (Integer) get(DST_PORT));
                if (sslProtocol != ProtocolsOverSsl.UNKNOWN) {
                    put(Packet.APP_LAYER_PROTOCOL, AppLayerProtocols.SSL);
                    put(Packet.PROTOCOL_OVER_SSL, sslProtocol);
                }

                ArrayList<JsonAdapter> payloads = new ArrayList<>();
                ArrayList<HashMap<String, Object>> records = new ArrayList<>();
                if (layers.isString(protocol)) {
                    return;
                }
                else if (layers.isArray(protocol)) {
                    payloads = layers.getLayersArray(protocol);
                } else {
                    payloads.add(layers.getLayer(protocol));
                }
                for (JsonAdapter item: payloads) {
                    SslJsonParser sslParser = new SslJsonParser(number);
                    records.addAll(sslParser.parse(item));
                }
                put(SSL_RECORDS, records);
                break;
            case SMTP:
            case POP3:
            case IMAP: break;
            default:
                LOG.info(getLogPrefix((Integer) get(NUMBER)) + "Not supported application layer protocol.");
                break;
        }

        if (parser != null) {
            this.putAll(parser);
        }
    }

    private AppLayerProtocols detectAppProtocol(JsonAdapter layers) {
        return Stream.of(AppLayerProtocols.values())
                .filter(x -> x != AppLayerProtocols.UNKNOWN)
                .filter(x -> layers.containsKey(x.name().toLowerCase()))
                .findFirst()
                .orElse(AppLayerProtocols.UNKNOWN);
    }

    private void parseUdp(JsonAdapter udp) {
        Integer number = (Integer) get(NUMBER);
        JsonHelper.addValue(number, this, SRC_PORT, udp, JSON_UDP_SRC_PORT, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(number, this, DST_PORT, udp, JSON_UDP_DST_PORT, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(number, this, UDPSUM, udp, JSON_UDP_CHECKSUM, JsonHelper.ValueTypes.INT);
        if ((Integer) get(UDPSUM) == 0) {
            remove(UDPSUM);
        }

        try {
            int udpLen = udp.getIntValue(JSON_UDP_LEN);
            put(UDP_LENGTH, udpLen - UDP_HEADER_SIZE);
            put(PAYLOAD_LEN, udpLen - UDP_HEADER_SIZE);
            put(LEN, udpLen - UDP_HEADER_SIZE);
        } catch (IllegalArgumentException e) {
            LOG.warn(getLogPrefix((Integer) get(NUMBER)) + "Missing value - " + PAYLOAD_LEN);
        }
    }

    private void parseTcp(JsonAdapter tcp) {
        Integer number = (Integer) get(NUMBER);
        JsonHelper.addValue(number, this, SRC_PORT, tcp, JSON_TCP_SRC_PORT, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(number, this, DST_PORT, tcp, JSON_TCP_DST_PORT, JsonHelper.ValueTypes.INT);

        JsonHelper.addValue(number, this, TCP_HEADER_LENGTH, tcp, JSON_TCP_HEADER_LEN, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(number, this, TCP_SEQ, tcp, JSON_TCP_SEQ, JsonHelper.ValueTypes.LONG);
        JsonHelper.addValue(number, this, TCP_ACK, tcp, JSON_TCP_ACK, JsonHelper.ValueTypes.INT);

        JsonHelper.addValue(number, this, PAYLOAD_LEN, tcp, JSON_TCP_PAYLOAD_LEN, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(number, this, LEN, tcp, JSON_TCP_PAYLOAD_LEN, JsonHelper.ValueTypes.INT);

        String payload;
        try {
            payload = tcp.getStringValue(JSON_TCP_PAYLOAD);
        } catch (IllegalArgumentException e) {
            payload = "";
        }
        put(TCP_HEX_PAYLOAD, payload.replace(":", ""));

        JsonHelper.addValue(number, this, TCP_FLAG_NS, tcp, JSON_TCP_FLAG_NS, JsonHelper.ValueTypes.BOOLEAN);
        JsonHelper.addValue(number, this, TCP_FLAG_CWR, tcp, JSON_TCP_FLAG_CWR, JsonHelper.ValueTypes.BOOLEAN);
        JsonHelper.addValue(number, this, TCP_FLAG_ECE, tcp, JSON_TCP_FLAG_ECE, JsonHelper.ValueTypes.BOOLEAN);
        JsonHelper.addValue(number, this, TCP_FLAG_URG, tcp, JSON_TCP_FLAG_URG, JsonHelper.ValueTypes.BOOLEAN);
        JsonHelper.addValue(number, this, TCP_FLAG_ACK, tcp, JSON_TCP_FLAG_ACK, JsonHelper.ValueTypes.BOOLEAN);
        JsonHelper.addValue(number, this, TCP_FLAG_PSH, tcp, JSON_TCP_FLAG_PSH, JsonHelper.ValueTypes.BOOLEAN);
        JsonHelper.addValue(number, this, TCP_FLAG_RST, tcp, JSON_TCP_FLAG_RST, JsonHelper.ValueTypes.BOOLEAN);
        JsonHelper.addValue(number, this, TCP_FLAG_SYN, tcp, JSON_TCP_FLAG_SYN, JsonHelper.ValueTypes.BOOLEAN);
        JsonHelper.addValue(number, this, TCP_FLAG_FIN, tcp, JSON_TCP_FLAG_FIN, JsonHelper.ValueTypes.BOOLEAN);
    }

    private void parseIpV4(JsonAdapter ipV4) {
        put(IP_VERSION, IPV4);
        Integer number = (Integer) get(NUMBER);
        JsonHelper.addValue(number, this, IP_HEADER_LENGTH, ipV4, JSON_IPV4_HEADER_LEN, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(number, this, SRC, ipV4, JSON_IPV4_SRC, JsonHelper.ValueTypes.STRING);
        JsonHelper.addValue(number, this, DST, ipV4, JSON_IPV4_DST, JsonHelper.ValueTypes.STRING);
        JsonHelper.addValue(number, this, TTL, ipV4, JSON_IPV4_TTL, JsonHelper.ValueTypes.INT);

        JsonHelper.addValue(number, this, IP_FLAGS_DF, ipV4, JSON_IPV4_FLAG_DF, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(number, this, IP_FLAGS_MF, ipV4, JSON_IPV4_FLAG_MF, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(number, this, FRAGMENT_OFFSET, ipV4, JSON_IPV4_FRAGMENT_OFFSET, JsonHelper.ValueTypes.INT);

        int flagMf = (int) get(IP_FLAGS_MF);
        int fragOffset = (int) get(FRAGMENT_OFFSET);
        if (flagMf > 0 || fragOffset > 0) {
            put(FRAGMENT, true);
            put(LAST_FRAGMENT, (flagMf == 0));
        } else {
            put(FRAGMENT, false);
        }

        JsonHelper.addValue(number, this, ID, ipV4, JSON_IPV4_ID, JsonHelper.ValueTypes.LONG);
        JsonHelper.addValue(number, this, PROTOCOL, ipV4, JSON_IPV4_PROTOCOL, JsonHelper.ValueTypes.STRING);
    }

    private void parseIpV6(JsonAdapter ipV6) {
        put(IP_VERSION, IPV6);
        Integer number = (Integer) get(NUMBER);
        JsonHelper.addValue(number, this, SRC, ipV6, JSON_IPV6_SRC, JsonHelper.ValueTypes.STRING);
        JsonHelper.addValue(number, this, DST, ipV6, JSON_IPV6_DST, JsonHelper.ValueTypes.STRING);
        JsonHelper.addValue(number, this, TTL, ipV6, JSON_IPV6_HOP_LIMIT, JsonHelper.ValueTypes.INT);

        if (ipV6.containsKey(JSON_IPV6_FRAGMENT_HEADER)) {
            put(FRAGMENT, true);
        } else {
            put(FRAGMENT, false);
            put(PROTOCOL, PROTOCOL_FRAGMENT);
        }
    }

}
