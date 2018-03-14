package org.ndx.model.parsers.applayer;

import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;
import org.ndx.model.json.JsonHelper;
import org.ndx.model.pcap.DnsPacket;
import org.xbill.DNS.Message;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class DnsParser extends AppLayerParser {

    private static final Log LOG = LogFactory.getLog(DnsParser.class);

    private static final String JSON_DNS_COUNT_QUERIES = "dns_dns_count_queries";
    private static final String JSON_DNS_COUNT_ANSWERS = "dns_dns_count_answers";
    private static final String JSON_DNS_QUERY_OR_RESPONSE = "dns_flags_dns_flags_response";
    private static final String JSON_DNS_ID = "dns_dns_id";
    private static final String JSON_DNS_QUERY_NAME = "text_dns_qry_name";
    private static final String JSON_DNS_QUERY_TYPE = "text_dns_qry_type";
    private static final String JSON_DNS_QUERY_CLASS = "text_dns_qry_class";
    private static final String JSON_DNS_RESP_NAME = "text_dns_resp_name";
    private static final String JSON_DNS_RESP_TYPE = "text_dns_resp_type";
    private static final String JSON_DNS_RESP_CLASS = "text_dns_resp_class";
    private static final String JSON_DNS_PREFIX = "text_dns_";

    private HashMap<String, Integer> rdataIndexes = new HashMap<>();

//    @Override
//    public void parse(byte[] payload) {
//        try {
//            Message dnsMsg = new Message(payload);
//            int i = 5;
//        } catch (IOException e) {
//            LOG.warn("Unable to parse DNS payload.");
//        }
//    }

    @Override
    public void parse(byte[] payload) {
        DnsPacket data = new DnsPacket(new ByteBufferKaitaiStream(payload));
        this.put(Packet.DNS_ANSWER_CNT, data.ancount());
        this.put(Packet.DNS_QUERY_CNT, data.qdcount());
        this.put(Packet.DNS_QUERY_OR_RESPONSE, data.flags().qr());
        this.put(Packet.DNS_ID, data.transactionId());
        addPcapQueries(data.queries());
        addPcapAnswers(data.answers());
    }

    @Override
    public void parse(Map<String, Object> payload) {
        JsonHelper.addIntValue(this, Packet.DNS_QUERY_OR_RESPONSE,
                (String) payload.get(JSON_DNS_QUERY_OR_RESPONSE));
        JsonHelper.addIntValue(this, Packet.DNS_ANSWER_CNT, (String) payload.get(JSON_DNS_COUNT_ANSWERS));
        JsonHelper.addIntValue(this, Packet.DNS_QUERY_CNT, (String) payload.get(JSON_DNS_COUNT_QUERIES));
        JsonHelper.addIntValue(this, Packet.DNS_ID, (String) payload.get(JSON_DNS_ID));
        parseJsonQueries(payload);
        parseJsonAnswers(payload);
    }

    private void addPcapQueries(ArrayList<DnsPacket.Query> qs) {
        ArrayList<String> queries = new ArrayList<>();
        if (qs != null) {
            for (DnsPacket.Query query : qs) {
                if (query.name() == null || query.type() ==null || query.queryClass() == null) {
                    continue;
                }
                queries.add(formatOutput(getPcapName(query.name()), Long.toString(query.type().id()),
                        Long.toString(query.queryClass().id())));
            }
        }
        this.put(Packet.DNS_QUERIES, queries);
    }

    private void addPcapAnswers(ArrayList<DnsPacket.Answer> as) {
        ArrayList<String> answers = new ArrayList<>();
        if (as != null) {
            for (DnsPacket.Answer answer: as) {
                if (answer.name() == null || answer.type() ==null || answer.answerClass() == null) {
                    continue;
                }
                answers.add(formatOutput(getPcapName(answer.name()), Long.toString(answer.type().id()),
                        Long.toString(answer.answerClass().id())));
            }
        }
        this.put(Packet.DNS_ANSWERS, answers);
    }

    private String getPcapName(DnsPacket.DomainName name) {
        String delimiter = "";
        StringBuilder sb = new StringBuilder();
        for (DnsPacket.Label label: name.name()) {
            if (label.isPointer()) {
                sb.append(getPcapName(label.pointer().contents()));
            } else {
                if (!label.name().isEmpty()) {
                    sb.append(delimiter);
                }
                delimiter = ".";
                sb.append(label.name());
            }
        }
        return sb.toString();
    }


    /**
     * One packet may contain one or more DNS queries. This is allowed by protocol, but not supported by nameservers.
     * @param payload DNS payload.
     */
    @SuppressWarnings("unchecked")
    private void parseJsonQueries(Map<String, Object> payload) {
        int qCnt = (int) get(Packet.DNS_QUERY_CNT);
        List<String> queries = new ArrayList<>();
        if (qCnt == 0) {
            LOG.warn("Malformed DNS packet: missing query in DNS payload.");
        } else if (qCnt == 1) {
            String name = checkJsonString(payload, JSON_DNS_QUERY_NAME);
            String type = checkJsonString(payload, JSON_DNS_QUERY_TYPE);
            String cls = checkJsonString(payload, JSON_DNS_QUERY_CLASS);
            queries.add(formatOutput(name, type, cls));
        } else {
            ArrayList<String> names = checkJsonArray(payload, JSON_DNS_QUERY_NAME);
            ArrayList<String> types = checkJsonArray(payload, JSON_DNS_QUERY_TYPE);
            ArrayList<String> classes = checkJsonArray(payload, JSON_DNS_QUERY_CLASS);
            if (names != null && types != null && classes != null) {
                Iterator<String> itNames = names.iterator();
                Iterator<String> itTypes = types.iterator();
                Iterator<String> itClasses = classes.iterator();
                while (itNames.hasNext() && itTypes.hasNext() && itClasses.hasNext()) {
                    queries.add(formatOutput(itNames.next(), itTypes.next(), itClasses.next()));
                }
            }
        }
        put(Packet.DNS_QUERIES, queries);
    }

    @SuppressWarnings("unchecked")
    private void parseJsonAnswers(Map<String, Object> payload) {
        int aCnt = (int) get(Packet.DNS_ANSWER_CNT);
        List<String> answers = new ArrayList<>();
        switch (aCnt) {
            case 0:
                break;
            case 1:
                String name = checkJsonString(payload, JSON_DNS_RESP_NAME);
                String type = checkJsonString(payload, JSON_DNS_RESP_TYPE);
                String cls = checkJsonString(payload, JSON_DNS_RESP_CLASS);
                String rdata = getJsonRdata(payload, type);
                answers.add(formatOutput(name, type, cls, rdata));
                break;
            default:
                answers = getJsonMultipleAnswers(payload, aCnt);
                break;
        }
        put(Packet.DNS_ANSWERS, answers);
    }

    @SuppressWarnings("unchecked")
    private List<String> getJsonMultipleAnswers(Map<String, Object> payload, int aCnt) {
        List<String> answers = new ArrayList<>();
        ArrayList<String> names = checkJsonArray(payload, JSON_DNS_RESP_NAME);
        ArrayList<String> types = checkJsonArray(payload, JSON_DNS_RESP_TYPE);
        ArrayList<String> classes = checkJsonArray(payload, JSON_DNS_RESP_CLASS);
        if (names != null && types != null && classes != null) {
            Iterator<String> itNames = names.iterator();
            Iterator<String> itTypes = types.iterator();
            Iterator<String> itClasses = classes.iterator();
            int i = 0;

            while (itNames.hasNext() && itTypes.hasNext() && itClasses.hasNext() && i < aCnt) {
                String type = itTypes.next();
                String rdata = getJsonRdata(payload, type);
                answers.add(formatOutput(itNames.next(), type, itClasses.next(), rdata));
                i++;
            }
        }
        return answers;
    }

    private String checkJsonString(Map<String, Object> map, String key) {
        return map.get(key) instanceof String ? (String)map.get(key) : "";
    }

    @SuppressWarnings("unchecked")
    private ArrayList<String> checkJsonArray(Map<String, Object> map, String key) {
        return map.get(key) instanceof ArrayList ? (ArrayList<String>)map.get(key) : null;
    }

    private String getJsonRdata(Map<String, Object> payload, String id) {
        StringBuilder output = new StringBuilder();
        try {
            String type = DnsHelper.idToType(id);
            List<String> keySet = payload.keySet()
                    .stream()
                    .filter(s -> s.startsWith(JSON_DNS_PREFIX + type.toLowerCase()))
                    .collect(Collectors.toList());
            String delimiter = "";
            for (String key: keySet) {
                Integer index = rdataIndexes.get(key);
                if (index == null) {
                    rdataIndexes.put(key, 0);
                    index = 0;
                } else {
                    rdataIndexes.put(key, ++index);
                }
                String rdata;
                ArrayList<String> rdataArr = checkJsonArray(payload, key);
                if (rdataArr == null) {
                    rdata = checkJsonString(payload, key);
                } else {
                    rdata = rdataArr.get(index);
                }
                output.append(delimiter);
                delimiter = " ";
                output.append(rdata);
            }
        } catch (NumberFormatException e) {
            LOG.warn("Malformed DNS packet: " + e.getMessage());
        }
        return output.toString();
    }

    private String formatOutput(String name,  String type, String cls) {
        return formatOutput(name, type, cls, "");
    }

    private String formatOutput(String name, String type, String cls, String rdata) {
        String output = "";
        try {
            output = name + "," + DnsHelper.idToType(type) + "," + DnsHelper.idToClass(cls);
            if (rdata != null && !rdata.isEmpty()) {
                output += "," + rdata;
            }
        } catch (NumberFormatException e) {
            LOG.warn("Malformed DNS packet: " + e.getMessage());
        }
        return output;
    }

}
