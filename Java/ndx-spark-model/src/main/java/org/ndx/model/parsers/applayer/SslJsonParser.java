package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;
import org.ndx.model.json.JsonAdapter;

import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

public class SslJsonParser extends AppLayerParser {

    private static final Log LOG = LogFactory.getLog(SslJsonParser.class);

    //    Record Type Values       dec      hex
    // -------------------------------------
    //    CHANGE_CIPHER_SPEC        20     0x14
    //    ALERT                     21     0x15
    //    HANDSHAKE                 22     0x16
    //    APPLICATION_DATA          23     0x17
    //
    //    Version Values            dec     hex
    // -------------------------------------
    //    SSL 3.0                   3,0  0x0300
    //    TLS 1.0                   3,1  0x0301
    //    TLS 1.1                   3,2  0x0302
    //    TLS 1.2                   3,3  0x0303

    private static final String SSL_JSON_CONTENT_TYPE = "ssl_record_ssl_record_content_type";
    private static final String SSL_JSON_VERSION = "ssl_record_ssl_record_version";
    private static final String SSL_JSON_RECORD_LENGTH = "ssl_record_ssl_record_length";
    private static final String SSL_JSON_CIPHER_SUITE = "ssl_handshake_ssl_handshake_ciphersuite";
    private static final String SSL_JSON_NOT_BEFORE_UTC = "x509af_notBefore_x509af_utcTime";
    private static final String SSL_JSON_NOT_AFTER_UTC = "x509af_notAfter_x509af_utcTime";

    public SslJsonParser(Integer packetNo) {
        packetNumber = packetNo != null ? packetNo : 0;
    }

    public SslJsonParser() {
    }

    /**
     * One json ssl layer may contain more records. This function attempts to extract
     * all available information. Each type of output is represented by one array.
     * Output values are independent and cannot be reliably paired together.
     *
     * @param payload Ssl/tls payload of json packet.
     * @return Parsed supported values.
     */
    public HashMap<String, ArrayList> parse(JsonAdapter payload) {
        HashMap<String, ArrayList> records = new HashMap<>();

        records.put(Packet.SSL_CONTENT_TYPES, getRecordValues(payload, SSL_JSON_CONTENT_TYPE));
        records.put(Packet.SSL_VERSIONS, getRecordValues(payload, SSL_JSON_VERSION)
                .stream().map(SslHelper::decodeSslVersion)
                .collect(Collectors.toCollection(ArrayList::new)));
        records.put(Packet.SSL_RECORD_LENGTHS, getRecordValues(payload, SSL_JSON_RECORD_LENGTH));
        records.put(Packet.SSL_CIPHER_SUITES, getRecordValues(payload, SSL_JSON_CIPHER_SUITE)
                .stream().map(SslHelper::cipherSuiteDecToString)
                .collect(Collectors.toCollection(ArrayList::new)));

        Iterator<String> datesBefore = getRecordValues(payload, SSL_JSON_NOT_BEFORE_UTC).iterator();
        Iterator<String> datesAfter = getRecordValues(payload, SSL_JSON_NOT_AFTER_UTC).iterator();
        ArrayList<Long> intervals = new ArrayList<>();
        while (datesBefore.hasNext() && datesAfter.hasNext()) {
            Date before, after;
            try {
                before = SslHelper.parseDate(datesBefore.next());
                after = SslHelper.parseDate(datesAfter.next());
            } catch (ParseException e) {
                continue;
            }
            intervals.add(after.getTime() - before.getTime());
        }
        records.put(Packet.SSL_INTERVALS, intervals);

        return records;
    }

    /**
     * @param payload Json ssl payload.
     * @param key     Key with which is associated with desired value.
     * @return All values associated with key.
     */
    private ArrayList<String> getRecordValues(JsonAdapter payload, String key) {
        ArrayList<String> values = new ArrayList<>();
        if (payload.isString(key)) {
            values.add(payload.getStringValue(key));
        } else if (payload.isArray(key)) {
            values = payload.getStringArray(key);
        }
        return values;
    }

}
