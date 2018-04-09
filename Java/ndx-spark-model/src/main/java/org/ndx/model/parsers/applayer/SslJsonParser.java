package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;
import org.ndx.model.json.JsonAdapter;

import java.util.*;

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

    private static final String SSL3_CODE = "0x0300";
    private static final String TLS1_CODE = "0x0301";
    private static final String TLS11_CODE = "0x0302";
    private static final String TLS12_CODE = "0x0303";

    private static final String SSL3 = "SSL 3";
    private static final String TLS1 = "TLS 1";
    private static final String TLS11 = "TLS 1.1";
    private static final String TLS12 = "TLS 1.2";

    private static final String SSL_JSON_CONTENT_TYPE = "ssl_record_ssl_record_content_type";
    private static final String SSL_JSON_VERSION = "ssl_record_ssl_record_version";
    private static final String SSL_JSON_RECORD_LENGTH = "ssl_record_ssl_record_length";

    public SslJsonParser(int packetNo) {
        packetNumber = packetNo;
    }

    public SslJsonParser() {}

    public ArrayList<HashMap<String, Object>> parse(JsonAdapter payload) {
        ArrayList<HashMap<String, Object>> records = new ArrayList<>();

        if (payload.isString(SSL_JSON_VERSION)) {
            try {
                HashMap<String, Object> ssl = createRecord(payload.getStringValue(SSL_JSON_VERSION),
                        payload.getIntValue(SSL_JSON_CONTENT_TYPE), payload.getIntValue(SSL_JSON_RECORD_LENGTH));
                records.add(ssl);
            } catch (Exception e) {
                LOG.warn(Packet.getLogPrefix(packetNumber) + e.getMessage());
            }
        } else if (payload.isArray(SSL_JSON_VERSION)) {
            try {
                Iterator<String> itVer = payload.getStringArray(SSL_JSON_VERSION).iterator();
                Iterator<String> itType = payload.getStringArray(SSL_JSON_CONTENT_TYPE).iterator();
                Iterator<String> itLen = payload.getStringArray(SSL_JSON_RECORD_LENGTH).iterator();

                while (itVer.hasNext() && itType.hasNext() && itLen.hasNext()) {
                    int type, len;
                    String msg = SSL_JSON_CONTENT_TYPE;
                    try {
                        type = Integer.decode(itType.next());
                        msg = SSL_JSON_RECORD_LENGTH;
                        len = Integer.decode(itLen.next());
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("Missing value - " + msg, e);
                    }
                    HashMap<String, Object> ssl = createRecord(itVer.next(), type, len);
                    records.add(ssl);
                }
            } catch (IllegalArgumentException e) {
                LOG.warn(Packet.getLogPrefix(packetNumber) + e.getMessage());
            }
        }
        return records;
    }

    private HashMap<String, Object> createRecord(String version, int contentType, int len) {
        HashMap<String, Object> record = new HashMap<>();
        record.put(Packet.SSL_VERSION, decodeSslVersion(version));
        record.put(Packet.SSL_CONTENT_TYPE, contentType);
        record.put(Packet.SSL_RECORD_LENGTH, len);
        return record;
    }

    private String decodeSslVersion(String hexVersion) {
        if (hexVersion == null) {
            return "";
        }
        switch (hexVersion) {
            case SSL3_CODE:
                return SSL3;
            case TLS1_CODE:
                return TLS1;
            case TLS11_CODE:
                return TLS11;
            case TLS12_CODE:
                return TLS12;
        }
        return "";
    }

}
