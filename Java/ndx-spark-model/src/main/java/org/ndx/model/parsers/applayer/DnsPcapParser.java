package org.ndx.model.parsers.applayer;

import org.ndx.model.Packet;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;


public class DnsPcapParser extends AppLayerParser {

    private static final int PCAP_DNS_COUNT_QUERIES = 0;
    private static final int PCAP_DNS_COUNT_ASWERS = 1;
    private static final int PCAP_DNS_QUERY_SECTION = 0;
    private static final int PCAP_DNS_ANSWER_SECTION = 1;
    private static final int PCAP_DNS_QR_FLAG = 0;

    /**
     * Attempts to parse DNS packet from binary (pcap) source.
     *
     * @param payload Binary representation of the DNS payload.
     * @throws IllegalArgumentException Has been thrown when DNS packet is malformed.
     */
    public void parse(byte[] payload) throws IllegalArgumentException {
        try {
            Message dnsMsg = new Message(payload);
            Header dnsHeader = dnsMsg.getHeader();
            put(Packet.DNS_ID, dnsHeader.getID());
            put(Packet.DNS_QUERY_CNT, dnsHeader.getCount(PCAP_DNS_COUNT_QUERIES));
            put(Packet.DNS_ANSWER_CNT, dnsHeader.getCount(PCAP_DNS_COUNT_ASWERS));
            put(Packet.DNS_IS_RESPONSE, dnsHeader.getFlag(PCAP_DNS_QR_FLAG));
            put(Packet.DNS_QUERIES, parseSection(dnsMsg.getSectionArray(PCAP_DNS_QUERY_SECTION)));
            put(Packet.DNS_ANSWERS, parseSection(dnsMsg.getSectionArray(PCAP_DNS_ANSWER_SECTION)));
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Attempts to parse query or answer section of DNS packet.
     *
     * @param section Query or answer section.
     * @return CSV formatted output. This format is the same as in json.
     */
    private ArrayList<String> parseSection(Record[] section) {
        String[] records = Arrays.stream(section)
                .map(record -> DnsHelper.formatOutput(record.getName().toString(true),
                        Integer.toString(record.getType()), Integer.toString(record.getDClass()),
                        record.rdataToString()))
                .toArray(String[]::new);
        return new ArrayList<>(Arrays.asList(records));
    }

}
