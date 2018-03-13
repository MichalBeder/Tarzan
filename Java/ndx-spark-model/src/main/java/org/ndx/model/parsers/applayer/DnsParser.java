package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;
import org.ndx.model.json.JsonHelper;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.ArrayList;

import java.util.List;
import java.util.Map;

public class DnsParser extends AppLayerParser {

    private static final Log LOG = LogFactory.getLog(DnsParser.class);

    private static final String JSON_DNS_COUNT_QUERIES = "dns_dns_count_queries";
    private static final String JSON_DNS_COUNT_ANSWERS = "dns_dns_count_answers";
    private static final String JSON_DNS_QUERY_OR_RESPONSE = "dns_flags_dns_flags_response";
    private static final String JSON_DNS_ID = "dns_dns_id";
    private static final String JSON_DNS_TEXT = "text_text";
    private static final String JSON_DNS_QUERY_NAME = "text_dns_qry_name";
    private static final String JSON_DNS_QUERY_TYPE = "text_dns_qry_type";
    private static final String JSON_DNS_QUERY_CLASS = "text_dns_qry_class";
    private static final String JSON_DNS_RESP_NAME = "text_dns_resp_name";
    private static final String JSON_DNS_RESP_TYPE = "text_dns_resp_type";
    private static final String JSON_DNS_RESP_CLASS = "text_dns_resp_class";
    private static final String JSON_DNS_PREFIX = "text_dns_";

    @Override
    public void parse(byte[] payload) {
        throw new NotImplementedException();
    }

    @Override
    public void parse(Map<String, Object> payload) {
        JsonHelper.addIntValue(this, Packet.DNS_QUERY_OR_RESPONSE,
                (String) payload.get(JSON_DNS_QUERY_OR_RESPONSE));
        JsonHelper.addIntValue(this, Packet.DNS_ANSWER_CNT, (String) payload.get(JSON_DNS_COUNT_ANSWERS));
        JsonHelper.addIntValue(this, Packet.DNS_QUERY_CNT, (String) payload.get(JSON_DNS_COUNT_QUERIES));
        JsonHelper.addIntValue(this, Packet.DNS_ID, (String) payload.get(JSON_DNS_ID));
        parseJsonSections(payload);
    }

    /**
     * One packet may contain one or more DNS queries. This is allowed by protocol, but not supported by nameservers.
     * @param payload DNS payload.
     */
    @SuppressWarnings("unchecked")
    private void parseJsonSections(Map<String, Object> payload) {
        int qCnt = (int) get(Packet.DNS_QUERY_CNT);
        int aCnt = (int) get(Packet.DNS_ANSWER_CNT);
        List<String> queries = new ArrayList<>();
        List<String> answers = new ArrayList<>();
        if (qCnt == 0) {
            LOG.warn("Malformed DNS packet: missing query in DNS payload.");
            return;
        }
        ArrayList<String> texts = (payload.get(JSON_DNS_TEXT) instanceof ArrayList ?
                (ArrayList<String>)payload.get(JSON_DNS_TEXT) : null);
        if (texts == null) { // packet contains only DNS query
            queries.add(payload.get(JSON_DNS_TEXT) instanceof String ? (String) payload.get(JSON_DNS_TEXT) : "");
        } else {
            int i = 0;
            // JSON has the same attribute "text_text" for all sections (query, answer, authoritative and additional)
            for (String text: texts) {
                if (i < qCnt) {
                    queries.add(text);
                } else if (i++ < qCnt + aCnt) {
                    answers.add(text);
                }
            }
        }
        put(Packet.DNS_QUERIES, queries);
        put(Packet.DNS_ANSWERS, answers);
    }

}
