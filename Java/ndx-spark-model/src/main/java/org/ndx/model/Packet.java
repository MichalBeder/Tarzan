package org.ndx.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.pcap.PacketModel;

import java.util.HashMap;
import java.util.Map;

public abstract class Packet extends HashMap<String, Object> {

    protected static final Log LOG = LogFactory.getLog(Packet.class);

    public static final String PROTOCOL_ICMP = "ICMP";
    public static final String PROTOCOL_TCP = "TCP";
    public static final String PROTOCOL_UDP = "UDP";
    public static final String PROTOCOL_FRAGMENT = "Fragment";
    protected static Map<Integer, String> protocols;
    static {
        protocols = new HashMap<Integer, String>();
        protocols.put(1, PROTOCOL_ICMP);
        protocols.put(6, PROTOCOL_TCP);
        protocols.put(17, PROTOCOL_UDP);
        protocols.put(44, PROTOCOL_FRAGMENT);
    }

    public enum AppLayerProtocols {
        NOT_SUPPORTED,
        DNS,
        HTTP,
        HTTPS,
        SMTP,
        POP3,
        IMAP,
        TLS
    }
    public static final String APP_LAYER_PROTOCOL = "app_protocol";

    public static final String TIMESTAMP = "ts";
    public static final String TIMESTAMP_USEC = "ts_usec";
    public static final String TIMESTAMP_MICROS = "ts_micros";
    public static final String NUMBER = "number";

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
    public static final int UDP_HEADER_SIZE = 8;

    /*** Application layer ***/
    /* DNS */
    public static final String DNS_ANSWER_CNT = "dns_answer_cnt";
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

    public void parsePacket(String frame) {}
    public void parsePacket(PacketModel.RawFrame frame) {}
}
