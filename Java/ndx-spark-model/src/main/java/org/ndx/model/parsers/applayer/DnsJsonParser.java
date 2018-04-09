package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;
import org.ndx.model.json.JsonAdapter;
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

    public DnsJsonParser(int packetNo) {
        packetNumber = packetNo;
        init();
    }

    public DnsJsonParser() {
        init();
    }

    private void init() {
        put(Packet.DNS_QUERIES, new ArrayList<>());
        put(Packet.DNS_ANSWERS, new ArrayList<>());
        put(Packet.DNS_QUERY_CNT, 0);
        put(Packet.DNS_ANSWER_CNT, 0);
        put(Packet.DNS_AUTH_CNT, 0);
        put(Packet.DNS_ADD_CNT, 0);
    }

    public void parse(JsonAdapter payload) {
        JsonHelper.addValue(packetNumber, this, Packet.DNS_ID, payload, JSON_DNS_ID, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(packetNumber, this, Packet.DNS_IS_RESPONSE, payload,
                JSON_DNS_QUERY_OR_RESPONSE, JsonHelper.ValueTypes.BOOLEAN);

        JsonHelper.addValue(packetNumber, this, Packet.DNS_QUERY_CNT, payload,
                JSON_DNS_COUNT_QUERIES, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(packetNumber, this, Packet.DNS_ANSWER_CNT, payload,
                JSON_DNS_COUNT_ANSWERS, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(packetNumber, this, Packet.DNS_AUTH_CNT, payload,
                JSON_DNS_COUNT_AUTH, JsonHelper.ValueTypes.INT);
        JsonHelper.addValue(packetNumber, this, Packet.DNS_ADD_CNT, payload,
                JSON_DNS_COUNT_ADD, JsonHelper.ValueTypes.INT);

        parseJsonQueries(payload);
        parseJsonAnswers(payload);
    }

    /**
     * One packet may contain one or more DNS queries. This is allowed by protocol, but not supported by nameservers.
     * @param payload DNS payload.
     */
    @SuppressWarnings("unchecked")
    private void parseJsonQueries(JsonAdapter payload) {
        int qCnt = (int) get(Packet.DNS_QUERY_CNT);
        List<String> queries = (ArrayList<String>) get(Packet.DNS_QUERIES);
        if (qCnt == 0) {
            LOG.warn(Packet.getLogPrefix(packetNumber) + "Malformed DNS packet: missing query in DNS payload.");
        } else if (qCnt == 1) {
            try {
                String name = payload.getStringValue(JSON_DNS_QUERY_NAME);
                String type = payload.getStringValue(JSON_DNS_QUERY_TYPE);
                String cls = payload.getStringValue(JSON_DNS_QUERY_CLASS);
                queries.add(DnsHelper.formatOutput(name, type, cls));
            } catch (Exception e) {
                LOG.warn(Packet.getLogPrefix(packetNumber) + e.getMessage());
            }
        } else {
            try {
                ArrayList<String> names = payload.getStringArray(JSON_DNS_QUERY_NAME);
                ArrayList<String> types = payload.getStringArray(JSON_DNS_QUERY_TYPE);
                ArrayList<String> classes = payload.getStringArray(JSON_DNS_QUERY_CLASS);

                Iterator<String> itNames = names.iterator();
                Iterator<String> itTypes = types.iterator();
                Iterator<String> itClasses = classes.iterator();

                while (itNames.hasNext() && itTypes.hasNext() && itClasses.hasNext()) {
                    queries.add(DnsHelper.formatOutput(itNames.next(), itTypes.next(), itClasses.next()));
                }
            } catch (Exception e) {
                LOG.warn(Packet.getLogPrefix(packetNumber) + e.getMessage());
            }
        }
        put(Packet.DNS_QUERIES, queries);
    }

    private void parseJsonAnswers(JsonAdapter payload) {
        rdataIndex = (int) get(Packet.DNS_QUERY_CNT);
        int allCnt = getAllAnswerSecCnt();
        switch (allCnt) {
            case 0:
                break;
            case 1:
                getJsonAnswer(payload);
                break;
            default:
                getJsonMultipleAnswers(payload);
                rdataIndex = 0;
                break;
        }
    }

    @SuppressWarnings("unchecked")
    private void getJsonAnswer(JsonAdapter payload) {
        int aCnt = (int) get(Packet.DNS_ANSWER_CNT);
        if (aCnt == 1) {
            List<String> answers = (List<String>) get(Packet.DNS_ANSWERS);
            try {
                String name = payload.getStringValue(JSON_DNS_RESP_NAME);
                String type = payload.getStringValue(JSON_DNS_RESP_TYPE);
                String cls = payload.getStringValue(JSON_DNS_RESP_CLASS);
                String rdata = getJsonRdata(payload);
                answers.add(DnsHelper.formatOutput(name, type, cls, rdata));
            } catch (Exception e) {
                LOG.warn(Packet.getLogPrefix(packetNumber) + e.getMessage());
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void getJsonMultipleAnswers(JsonAdapter payload) {
        List<String> answers = (List<String>) get(Packet.DNS_ANSWERS);
        int aCnt = (int) get(Packet.DNS_ANSWER_CNT);
        try {
            Iterator<String> itNames = payload.getStringArray(JSON_DNS_RESP_NAME).iterator();
            Iterator<String> itTypes = payload.getStringArray(JSON_DNS_RESP_TYPE).iterator();
            Iterator<String> itClasses = payload.getStringArray(JSON_DNS_RESP_CLASS).iterator();
            int i = 0;

            while (itNames.hasNext() && itTypes.hasNext() && itClasses.hasNext() && i < aCnt) {
                String type = itTypes.next();
                String rdata = getJsonRdata(payload);
                answers.add(DnsHelper.formatOutput(itNames.next(), type, itClasses.next(), rdata));
                i++;
            }
        } catch (Exception e) {
            LOG.warn(Packet.getLogPrefix(packetNumber) + e.getMessage());
        }
    }

    private String getJsonRdata(JsonAdapter payload) {
        String output = "";
        ArrayList<String> rdataArr = payload.getStringArray(JSON_DNS_TEXT);

        String text = rdataArr.get(rdataIndex++);
        String[] splits = text.split(",");
        if (splits.length > 2) {
            output = splits[splits.length - 1].trim();
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
