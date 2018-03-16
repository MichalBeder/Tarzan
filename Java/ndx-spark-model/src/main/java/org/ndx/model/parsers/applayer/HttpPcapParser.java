package org.ndx.model.parsers.applayer;

import org.apache.http.*;
import org.apache.http.impl.io.DefaultHttpRequestParser;
import org.apache.http.impl.io.DefaultHttpResponseParser;
import org.apache.http.impl.io.HttpTransportMetricsImpl;
import org.apache.http.impl.io.SessionInputBufferImpl;
import org.ndx.model.Packet;

import java.io.ByteArrayInputStream;
import java.io.IOException;


public class HttpPcapParser extends AppLayerParser  {

    private static final String HTTP_PCAP_HOST = "Host";

    public void parse(byte[] payload) throws IllegalArgumentException {
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

    private void tryParsePcapHttpRequest(byte[] payload) throws IOException, HttpException, IllegalArgumentException {
        SessionInputBufferImpl buffer = getSessionBuffer(payload);
        DefaultHttpRequestParser requestParser = new DefaultHttpRequestParser(buffer);
        HttpRequest request = requestParser.parse();
        put(Packet.HTTP_VERSION, getProtocolVersion(request.getRequestLine().getProtocolVersion()));
        put(Packet.HTTP_IS_RESPONSE, false);
        put(Packet.HTTP_METHOD, request.getRequestLine().getMethod());
        Header[] headers = request.getAllHeaders();
        String host = "";
        for (Header header: headers) {
            if (header.getName().equals(HTTP_PCAP_HOST)) {
                host = header.getValue();
            }
        }
        put(Packet.HTTP_URL, host);
    }

    private void tryParsePcapHttpResponse(byte[] payload) throws IOException, HttpException, IllegalArgumentException {
        SessionInputBufferImpl buffer = getSessionBuffer(payload);
        DefaultHttpResponseParser responseParser = new DefaultHttpResponseParser(buffer);
        HttpResponse response = responseParser.parse();
        put(Packet.HTTP_VERSION, getProtocolVersion(response.getProtocolVersion()));
        put(Packet.HTTP_IS_RESPONSE, true);
    }

    private SessionInputBufferImpl getSessionBuffer(byte[] payload) throws IllegalArgumentException {
        SessionInputBufferImpl buffer;
        ByteArrayInputStream stream = new ByteArrayInputStream(payload);
        HttpTransportMetricsImpl metrics = new HttpTransportMetricsImpl();
        buffer = new SessionInputBufferImpl(metrics, payload.length);
        buffer.bind(stream);
        return buffer;
    }

    private String getProtocolVersion(ProtocolVersion pVersion) {
        int major = pVersion.getMajor();
        int minor = pVersion.getMinor();
        return pVersion.getProtocol() + "/" + Integer.toString(major) + "." + Integer.toString(minor);
    }

}
