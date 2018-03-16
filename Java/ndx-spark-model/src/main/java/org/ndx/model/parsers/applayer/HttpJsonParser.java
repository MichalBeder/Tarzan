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

    public void parse(Map<String, Object> payload) throws IllegalAccessException {
        Object request = payload.get(HTTP_JSON_REQUEST);
        Object response = payload.get(HTTP_JSON_RESPONSE);
        if (request == null && response == null) {
            throw new IllegalAccessException("Http packet is neither a request nor a response");
        }
        if (request != null) {
            put(Packet.HTTP_IS_RESPONSE, false);
            JsonHelper.addStringValue(this, Packet.HTTP_URL, (String) payload.get(HTTP_JSON_HOST));
            JsonHelper.addStringValue(this, Packet.HTTP_METHOD, (String) payload.get(HTTP_JSON_METHOD));

        } else {
            put(Packet.HTTP_IS_RESPONSE, true);
        }
        JsonHelper.addStringValue(this, Packet.HTTP_VERSION, (String) payload.get(HTTP_JSON_VERSION));
    }
}
