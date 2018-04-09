package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;
import org.ndx.model.json.JsonAdapter;
import org.ndx.model.json.JsonHelper;

public class HttpJsonParser extends AppLayerParser {
    private static final Log LOG = LogFactory.getLog(HttpJsonParser.class);

    private static final String HTTP_JSON_REQUEST = "http_http_request";
    private static final String HTTP_JSON_RESPONSE = "http_http_response";
    private static final String HTTP_JSON_VERSION = "text_http_request_version";
    private static final String HTTP_JSON_METHOD = "text_http_request_method";
    private static final String HTTP_JSON_HOST = "http_http_host";

    public HttpJsonParser(int packetNo) {
        packetNumber = packetNo;
    }

    public HttpJsonParser() {}

    public void parse(JsonAdapter payload) {
        boolean isRequest = payload.containsKey(HTTP_JSON_REQUEST);
        boolean isResponse = payload.containsKey(HTTP_JSON_RESPONSE);

        if (isRequest) {
            put(Packet.HTTP_IS_RESPONSE, false);
            JsonHelper.addValue(packetNumber,this, Packet.HTTP_URL, payload, HTTP_JSON_HOST,
                    JsonHelper.ValueTypes.STRING);
            JsonHelper.addValue(packetNumber,this, Packet.HTTP_METHOD, payload,
                    HTTP_JSON_METHOD, JsonHelper.ValueTypes.STRING);
            JsonHelper.addValue(packetNumber,this, Packet.HTTP_VERSION, payload,
                    HTTP_JSON_VERSION, JsonHelper.ValueTypes.STRING);
        } else if (isResponse) {
            put(Packet.HTTP_IS_RESPONSE, true);
            JsonHelper.addValue(packetNumber,this, Packet.HTTP_VERSION, payload,
                    HTTP_JSON_VERSION, JsonHelper.ValueTypes.STRING);
        } else {
            LOG.warn(Packet.getLogPrefix(packetNumber) + "Http packet is neither a request nor a response.");
        }
    }
}
