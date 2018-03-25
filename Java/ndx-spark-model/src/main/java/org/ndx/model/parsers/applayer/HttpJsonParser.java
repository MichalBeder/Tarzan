package org.ndx.model.parsers.applayer;

import org.ndx.model.Packet;
import org.ndx.model.json.JsonHelper;

import java.util.Map;

public class HttpJsonParser extends AppLayerParser {

    private static final String HTTP_JSON_REQUEST = "http_http_request";
    private static final String HTTP_JSON_RESPONSE = "http_http_response";
    private static final String HTTP_JSON_VERSION = "text_http_request_version";
    private static final String HTTP_JSON_METHOD = "text_http_request_method";
    private static final String HTTP_JSON_HOST = "http_http_host";

    public void parse(Map<String, Object> payload) {
        Object request = payload.get(HTTP_JSON_REQUEST);
        Object response = payload.get(HTTP_JSON_RESPONSE);
        if (request == null && response == null) {
            throw new IllegalArgumentException("Http packet is neither a request nor a response");
        }
        if (request != null) {
            put(Packet.HTTP_IS_RESPONSE, false);
            put(Packet.HTTP_URL, JsonHelper.getStringValue(Packet.HTTP_URL, payload.get(HTTP_JSON_HOST)));
            put(Packet.HTTP_METHOD, JsonHelper.getStringValue(Packet.HTTP_METHOD, payload.get(HTTP_JSON_METHOD)));

        } else {
            put(Packet.HTTP_IS_RESPONSE, true);
        }
        put(Packet.HTTP_VERSION, JsonHelper.getStringValue(Packet.HTTP_VERSION, payload.get(HTTP_JSON_VERSION)));
    }
}
