package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;
import org.ndx.model.json.JsonHelper;

import java.util.*;

public class DnsJsonParser extends AppLayerParser {

    private static final Log LOG = LogFactory.getLog(DnsJsonParser.class);

    private static final String JSON_DNS_COUNT_QUERIES = "dns_dns_count_queries";
    private static final String JSON_DNS_COUNT_ANSWERS = "dns_dns_count_answers";
    private static final String JSON_DNS_COUNT_AUTH = "dns_dns_count_auth_rr";
    private static final String JSON_DNS_COUNT_ADD = "dns_dns_count_add_rr";
    private static final String JSON_DNS_QUERY_OR_RESPONSE = "dns_flags_dns_flags_response";
    private static final String JSON_DNS_ID = "dns_dns_id";
    private static final String JSON_DNS_QUERY_NAME = "text_dns_qry_name";
    private static final String JSON_DNS_QUERY_TYPE = "text_dns_qry_type";
    private static final String JSON_DNS_QUERY_CLASS = "text_dns_qry_class";
    private static final String JSON_DNS_RESP_NAME = "text_dns_resp_name";
    private static final String JSON_DNS_RESP_TYPE = "text_dns_resp_type";
    private static final String JSON_DNS_RESP_CLASS = "text_dns_resp_class";
    private static final String JSON_DNS_TEXT = "text_text";

    private int rdataIndex = 0;

    public void parse(Map<String, Object> payload) {
        put(Packet.DNS_QUERIES, new ArrayList<>());
        put(Packet.DNS_ANSWERS, new ArrayList<>());
        put(Packet.DNS_ID, JsonHelper.getIntValue(Packet.DNS_ID, payload.get(JSON_DNS_ID)));
        put(Packet.DNS_IS_RESPONSE, JsonHelper.getBoolValue(Packet.DNS_IS_RESPONSE,
                payload.get(JSON_DNS_QUERY_OR_RESPONSE)));
        put(Packet.DNS_QUERY_CNT, JsonHelper.getIntValue(Packet.DNS_QUERY_CNT,
                payload.get(JSON_DNS_COUNT_QUERIES), 0));
        put(Packet.DNS_ANSWER_CNT, JsonHelper.getIntValue(Packet.DNS_ANSWER_CNT,
                payload.get(JSON_DNS_COUNT_ANSWERS), 0));
        put(Packet.DNS_AUTH_CNT, JsonHelper.getIntValue(Packet.DNS_AUTH_CNT,
                payload.get(JSON_DNS_COUNT_AUTH), 0));
        put(Packet.DNS_ADD_CNT, JsonHelper.getIntValue(Packet.DNS_ADD_CNT,
                payload.get(JSON_DNS_COUNT_ADD), 0));

        parseJsonQueries(payload);
        parseJsonAnswers(payload);
    }

    /**
     * One packet may contain one or more DNS queries. This is allowed by protocol, but not supported by nameservers.
     * @param payload DNS payload.
     */
    @SuppressWarnings("unchecked")
    private void parseJsonQueries(Map<String, Object> payload) {
        int qCnt = (int) get(Packet.DNS_QUERY_CNT);
        List<String> queries = (List<String>) get(Packet.DNS_QUERIES);
        if (qCnt == 0) {
            LOG.warn("Malformed DNS packet: missing query in DNS payload.");
        } else if (qCnt == 1) {
            String name = JsonHelper.castString(payload, JSON_DNS_QUERY_NAME);
            String type = JsonHelper.castString(payload, JSON_DNS_QUERY_TYPE);
            String cls = JsonHelper.castString(payload, JSON_DNS_QUERY_CLASS);
            queries.add(DnsHelper.formatOutput(name, type, cls));
        } else {
            ArrayList<String> names = JsonHelper.castStringArray(payload, JSON_DNS_QUERY_NAME);
            ArrayList<String> types = JsonHelper.castStringArray(payload, JSON_DNS_QUERY_TYPE);
            ArrayList<String> classes = JsonHelper.castStringArray(payload, JSON_DNS_QUERY_CLASS);
            if (names != null && types != null && classes != null) {
                Iterator<String> itNames = names.iterator();
                Iterator<String> itTypes = types.iterator();
                Iterator<String> itClasses = classes.iterator();
                while (itNames.hasNext() && itTypes.hasNext() && itClasses.hasNext()) {
                    queries.add(DnsHelper.formatOutput(itNames.next(), itTypes.next(), itClasses.next()));
                }
            }
        }
        put(Packet.DNS_QUERIES, queries);
    }

    @SuppressWarnings("unchecked")
    private void parseJsonAnswers(Map<String, Object> payload) {
        rdataIndex = (int) get(Packet.DNS_QUERY_CNT);
        int allCnt = getAllAnswerSecCnt();
        List<String> answers = (List<String>) get(Packet.DNS_ANSWERS);
        switch (allCnt) {
            case 0:
                break;
            case 1:
                answers.add(getJsonAnswer(payload));
                break;
            default:
                answers.addAll(getJsonMultipleAnswers(payload));
                rdataIndex = 0;
                break;
        }
    }

    private String getJsonAnswer(Map<String, Object> payload) {
        String name = JsonHelper.castString(payload, JSON_DNS_RESP_NAME);
        String type = JsonHelper.castString(payload, JSON_DNS_RESP_TYPE);
        String cls = JsonHelper.castString(payload, JSON_DNS_RESP_CLASS);
        String rdata = getJsonRdata(payload);
        return DnsHelper.formatOutput(name, type, cls, rdata);
    }

    @SuppressWarnings("unchecked")
    private List<String> getJsonMultipleAnswers(Map<String, Object> payload) {
        int aCnt = (int) get(Packet.DNS_ANSWER_CNT);
        List<String> answers = new ArrayList<>();
        ArrayList<String> names = JsonHelper.castStringArray(payload, JSON_DNS_RESP_NAME);
        ArrayList<String> types = JsonHelper.castStringArray(payload, JSON_DNS_RESP_TYPE);
        ArrayList<String> classes = JsonHelper.castStringArray(payload, JSON_DNS_RESP_CLASS);

        if (names != null && types != null && classes != null) {
            Iterator<String> itNames = names.iterator();
            Iterator<String> itTypes = types.iterator();
            Iterator<String> itClasses = classes.iterator();
            int i = 0;

            while (itNames.hasNext() && itTypes.hasNext() && itClasses.hasNext() && i < aCnt) {
                String type = itTypes.next();
                String rdata = getJsonRdata(payload);
                answers.add(DnsHelper.formatOutput(itNames.next(), type, itClasses.next(), rdata));
                i++;
            }
        }
        return answers;
    }

    private String getJsonRdata(Map<String, Object> payload) {
        String output = "";
        ArrayList<String> rdataArr = JsonHelper.castStringArray(payload, JSON_DNS_TEXT);
        if (rdataArr == null) {
            LOG.warn("Malformed DNS packet: missing JSON text attribute.");
        } else {
            String text = rdataArr.get(rdataIndex++);
            String[] splits = text.split(",");
            if (splits.length > 2) {
                output = splits[splits.length - 1].trim();
            }
        }
        return output;
    }

    private int getAllAnswerSecCnt() {
        int ans = (int) get(Packet.DNS_ANSWER_CNT);
        int auth = (int) get(Packet.DNS_AUTH_CNT);
        int add = (int) get(Packet.DNS_ADD_CNT);
        return ans + auth + add;
    }

}
