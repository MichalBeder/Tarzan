package org.ndx.model;

import com.google.protobuf.ByteString;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.pcap.FlowModel;
import org.ndx.model.pcap.PacketModel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public abstract class Packet extends HashMap<String, Object> {

    protected static final Log LOG = LogFactory.getLog(Packet.class);

    public static final String PROTOCOL_ICMP = "ICMP";
    public static final String PROTOCOL_TCP = "TCP";
    public static final String PROTOCOL_UDP = "UDP";
    public static final String PROTOCOL_FRAGMENT = "Fragment";
    protected static Map<Integer, String> protocols;
    static {
        protocols = new HashMap<>();
        protocols.put(1, PROTOCOL_ICMP);
        protocols.put(6, PROTOCOL_TCP);
        protocols.put(17, PROTOCOL_UDP);
        protocols.put(44, PROTOCOL_FRAGMENT);
    }
    protected static final int IPV6_FRAGMENT_CODE = 44;

    public enum AppLayerProtocols {
        UNKNOWN,
        SSL,
        DNS,
        HTTP,
        SMTP,
        POP3,
        IMAP,
    }
    public static final String APP_LAYER_PROTOCOL = "app_protocol";

    public enum ProtocolsOverSsl {
        UNKNOWN,
        HTTPS,
        SMTP,
        POP3,
        IMAP,
    }
    public static final String PROTOCOL_OVER_SSL = "ssl_protocol";

    protected static final int HTTPS_PORT = 443;
    protected static final int SMTP_PORT_1 = 25;
    protected static final int SMTP_PORT_2 = 587;
    protected static final int SMTP_PORT_3 = 465;
    protected static final int IMAP_PORT_1 = 143;
    protected static final int IMAP_PORT_2 = 993;
    protected static final int POP3_PORT_1 = 110;
    protected static final int POP3_PORT_2 = 995;

    public static final String TIMESTAMP = "ts";
    public static final String TIMESTAMP_USEC = "ts_usec";
    public static final String TIMESTAMP_MICROS = "ts_micros";
    public static final String NUMBER = "number";
    public static final String FRAME_LENGTH = "frame_len";

    /*** Network layer ***/
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

    /*** Transport layer ***/
    public static final String SRC_PORT = "src_port";
    public static final String DST_PORT = "dst_port";
    public static final String TCP_HEADER_LENGTH = "tcp_header_length";
    public static final String TCP_SEQ = "tcp_seq";
    public static final String TCP_ACK = "tcp_ack";
    public static final String LEN = "len"; // TCP or UDP payload length
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
    public static final int UDP_HEADER_SIZE = 8;
    public static final String HEX_PAYLOAD = "tcp_payload"; // TCP or UDP payload in hex values

    /*** Application layer ***/

    /* DNS */
    public static final String DNS_ANSWER_CNT = "dns_answer_cnt";
    public static final String DNS_AUTH_CNT = "dns_auth_cnt";
    public static final String DNS_ADD_CNT = "dns_add_cnt";
    public static final String DNS_QUERY_CNT = "dns_query_cnt";
    public static final String DNS_IS_RESPONSE = "dns_query_response";
    public static final String DNS_ID = "dns_id";
    /* format: "name: type, class" */
    public static final String DNS_QUERIES = "dns_queries";
    /* format: "name: type, class, rdata" */
    public static final String DNS_ANSWERS = "dns_answers";
    /* HTTP */
    public static final String HTTP_VERSION = "http_version";
    public static final String HTTP_URL = "http_url";
    public static final String HTTP_PAYLOAD = "http_payload";
    public static final String HTTP_IS_RESPONSE = "http_is_response";
    public static final String HTTP_METHOD = "http_method";
    /* SSL */
    // array list of ssl records, one packet may contain one or more ssl records
    public static final String SSL_RECORDS = "ssl_records";
    public static final String SSL_CONTENT_TYPE = "ssl_content_type";
    public static final String SSL_VERSION = "ssl_version";
    public static final String SSL_RECORD_LENGTH = "ssl_record_length";

    public static FlowModel.FlowKey flowKeyParse(String flowkey) {
        String[] parts = flowkey.split("\\[|@|:|->|\\]");
        FlowModel.FlowKey.Builder fb = FlowModel.FlowKey.newBuilder();
        fb.setProtocol(ByteString.copyFromUtf8(parts[1]));
        fb.setSourceAddress(ByteString.copyFromUtf8(parts[2]));
        fb.setSourceSelector(ByteString.copyFromUtf8(parts[3]));
        fb.setDestinationAddress(ByteString.copyFromUtf8(parts[4]));
        fb.setDestinationSelector(ByteString.copyFromUtf8(parts[5]));
        return fb.build();
    }

    /**
     * Returns FlowKey for the current Packet.
     * @return FlowKey for the current Packet.
     */
    public FlowModel.FlowKey getFlowKey() {
        FlowModel.FlowKey.Builder fb = FlowModel.FlowKey.newBuilder();
        fb.setProtocol(ByteString.copyFromUtf8(get(PROTOCOL).toString()));
        fb.setSourceAddress(ByteString.copyFromUtf8(get(SRC).toString() ));
        fb.setSourceSelector(ByteString.copyFromUtf8(get(SRC_PORT).toString() ));
        fb.setDestinationAddress(ByteString.copyFromUtf8(get(DST).toString() ));
        fb.setDestinationSelector(ByteString.copyFromUtf8(get(DST_PORT).toString() ));
        return fb.build();
    }

    public String getSessionString() {
        String loAddress;
        String hiAddress;
        Integer loPort;
        Integer hiPort;
        if (((String)get(SRC)).compareTo((String)get(DST)) == 0) {
            loAddress = (String)get(SRC);
            hiAddress = (String)get(DST);
            if ((Integer)get(SRC_PORT) < (Integer)get(DST_PORT)) {
                loPort = (Integer)get(SRC_PORT);
                hiPort = (Integer)get(DST_PORT);
            } else {
                loPort = (Integer)get(DST_PORT);
                hiPort = (Integer)get(SRC_PORT);
            }
        }
        else if (((String)get(SRC)).compareTo((String)get(DST)) < 0) {
            loAddress = (String)get(SRC);
            loPort = (Integer)get(SRC_PORT);
            hiAddress = (String)get(DST);
            hiPort = (Integer)get(DST_PORT);
        } else {
            loAddress = (String)get(DST);
            loPort = (Integer)get(DST_PORT);
            hiAddress = (String)get(SRC);
            hiPort = (Integer)get(SRC_PORT);
        }

        return "[" +
                this.get(PROTOCOL) +
                "@" +
                loAddress +
                ":" +
                loPort +
                "<->" +
                hiAddress +
                ":" +
                hiPort +
                "]";
    }

    /**
     * Extends the collection of attributes of the current Packet with the provided colleciton.
     * @param prefix The prefix to be used when adding attributes. If null then no prefix will be used.
     * @param source The source collection of the attributes. It can be null.
     */
    public void extendWith(String prefix, HashMap<String,Object> source) {
        if (source == null) return;
        for (Map.Entry<String,Object> entry : source.entrySet()) {
            this.put(prefix == null ? entry.getKey() : prefix + "." + entry.getKey(), entry.getValue());
        }
    }

    public String getFlowString() {
        return "[" +
                this.get(PROTOCOL) +
                "@" +
                this.get(SRC) +
                ":" +
                this.get(SRC_PORT) +
                "->" +
                this.get(DST) +
                ":" +
                this.get(DST_PORT) +
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

    public Map<String, Integer> findKeyWords(ArrayList<String> keywords) {
        String payload = (String) get(HEX_PAYLOAD);
        if (payload == null) {
            return null;
        }
        Map<String, Integer> test = keywords.stream()
                .collect(Collectors.toMap(x -> x, x -> StringUtils.countMatches(payload, x)));
        return test;
    }

    public void parsePacket(String frame) {}
    public void parsePacket(PacketModel.RawFrame frame) {}
}
