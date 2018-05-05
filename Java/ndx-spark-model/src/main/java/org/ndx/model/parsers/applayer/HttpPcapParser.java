package org.ndx.model.parsers.applayer;

import org.apache.http.*;
import org.apache.http.impl.io.DefaultHttpRequestParser;
import org.apache.http.impl.io.DefaultHttpResponseParser;
import org.apache.http.impl.io.HttpTransportMetricsImpl;
import org.apache.http.impl.io.SessionInputBufferImpl;
import org.ndx.model.Packet;

import java.io.ByteArrayInputStream;
import java.io.IOException;


public class HttpPcapParser extends AppLayerParser {
    private static final String HTTP_PCAP_HOST = "Host";

    /**
     * Attempts to parse http packet from its binary representation. If the input packet
     * is malformed or it is not http packet, function throws IllegalArgumentException.
     *
     * @param payload Binary payload of the http packet.
     */
    public void parse(byte[] payload) {
        try {
            tryParsePcapHttpRequest(payload);
        } catch (IOException | HttpException | IllegalArgumentException e) {
            try {
                tryParsePcapHttpResponse(payload);
            } catch (IOException | HttpException | IllegalArgumentException ex) {
                throw new IllegalArgumentException(ex);
            }
        }
    }

    /**
     * Attempts to parse http request.
     *
     * @param payload Http payload in binary format.
     * @throws IOException   In case of an I/O error.
     * @throws HttpException In case of HTTP protocol violation.
     */
    private void tryParsePcapHttpRequest(byte[] payload) throws IOException, HttpException {
        SessionInputBufferImpl buffer = getSessionBuffer(payload);
        DefaultHttpRequestParser requestParser = new DefaultHttpRequestParser(buffer);
        HttpRequest request = requestParser.parse();
        put(Packet.HTTP_VERSION, getProtocolVersion(request.getRequestLine().getProtocolVersion()));
        put(Packet.HTTP_IS_RESPONSE, false);
        put(Packet.HTTP_METHOD, request.getRequestLine().getMethod());
        Header[] headers = request.getAllHeaders();
        String host = "";
        for (Header header : headers) {
            if (header.getName().equals(HTTP_PCAP_HOST)) {
                host = header.getValue();
            }
        }
        put(Packet.HTTP_URL, host);
    }

    /**
     * Attempts to parse http response.
     *
     * @param payload Http payload in binary format.
     * @throws IOException   In case of an I/O error.
     * @throws HttpException In case of HTTP protocol violation.
     */
    private void tryParsePcapHttpResponse(byte[] payload) throws IOException, HttpException {
        SessionInputBufferImpl buffer = getSessionBuffer(payload);
        DefaultHttpResponseParser responseParser = new DefaultHttpResponseParser(buffer);
        HttpResponse response = responseParser.parse();
        put(Packet.HTTP_VERSION, getProtocolVersion(response.getProtocolVersion()));
        put(Packet.HTTP_IS_RESPONSE, true);
    }

    /**
     * Initializes session buffer.
     *
     * @param payload Http payload in binary format.
     * @return Initialized session buffer.
     */
    private SessionInputBufferImpl getSessionBuffer(byte[] payload) {
        SessionInputBufferImpl buffer;
        ByteArrayInputStream stream = new ByteArrayInputStream(payload);
        HttpTransportMetricsImpl metrics = new HttpTransportMetricsImpl();
        buffer = new SessionInputBufferImpl(metrics, payload.length);
        buffer.bind(stream);
        return buffer;
    }

    /**
     * @param pVersion Version of http protocol.
     * @return Http version formatted into a string HTTP/<major>.<minor>.
     */
    private String getProtocolVersion(ProtocolVersion pVersion) {
        int major = pVersion.getMajor();
        int minor = pVersion.getMinor();
        return pVersion.getProtocol() + "/" + Integer.toString(major) + "." + Integer.toString(minor);
    }

}
