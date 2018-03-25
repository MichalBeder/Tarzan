package org.ndx.model.parsers.applayer;

import org.ndx.model.Packet;
import org.ndx.model.json.JsonHelper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@SuppressWarnings("unchecked")
public class SslJsonParser extends AppLayerParser {

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
    private static final String SSL_JSON_VERSION = "ssl_record_ssl_record_content_type";
    private static final String SSL_JSON_RECORD_LENGTH = "ssl_record_ssl_record_length";

    public void parse(Map<String, Object> payload) {
        ArrayList<HashMap> records = new ArrayList<>();
        Object ver = payload.get(SSL_JSON_VERSION);
        if (ver instanceof String) {
            HashMap<String, Object> ssl = createRecord(ver, payload.get(SSL_JSON_CONTENT_TYPE),
                    payload.get(SSL_JSON_RECORD_LENGTH));
            if (ssl != null) {
                records.add(ssl);
            }
        } else if (ver instanceof ArrayList) {
            ArrayList<String> version = (ArrayList<String>) ver;
            ArrayList<String> contentType = JsonHelper.castStringArray(payload, SSL_JSON_CONTENT_TYPE);
            ArrayList<String> length = JsonHelper.castStringArray(payload, SSL_JSON_RECORD_LENGTH);

            if (contentType != null && length != null) {
                Iterator<String> itVer = version.iterator();
                Iterator<String> itType = contentType.iterator();
                Iterator<String> itLen = length.iterator();

                while (itVer.hasNext() && itType.hasNext() && itLen.hasNext()) {
                    HashMap<String, Object> ssl = createRecord(itVer.next(), itType.next(), itLen.next());
                    if (ssl != null) {
                        records.add(ssl);
                    }
                }
            }
        }
        put(Packet.SSL_RECORDS, records);
    }

    private HashMap<String, Object> createRecord(Object version, Object contentType, Object len) {
        if (version == null || contentType == null || len == null) {
            return null;
        }
        HashMap<String, Object> record = new HashMap<>();
        record.put(Packet.SSL_VERSION, JsonHelper.getStringValue(Packet.SSL_VERSION,
                decodeSslVersion((String) version)));
        record.put(Packet.SSL_CONTENT_TYPE, JsonHelper.getIntValue(Packet.SSL_CONTENT_TYPE, contentType));
        record.put(Packet.SSL_RECORD_LENGTH, JsonHelper.getIntValue(Packet.SSL_RECORD_LENGTH, len));
        return record;
    }

    public void detectProtocol(Integer srcPort, Integer dstPort) {
        if (srcPort == null || dstPort == null) {
            return;
        }
        if (srcPort == 443 || dstPort == 443) {
            put(Packet.PROTOCOL_OVER_SSL, Packet.ProtocolsOverSsl.HTTPS);
        } else {
            put(Packet.PROTOCOL_OVER_SSL, Packet.ProtocolsOverSsl.UNKNOWN);
        }
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
