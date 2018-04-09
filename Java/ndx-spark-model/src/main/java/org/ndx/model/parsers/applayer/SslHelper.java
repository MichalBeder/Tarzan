package org.ndx.model.parsers.applayer;

import org.ndx.model.Packet;

public final class SslHelper {

    public static Packet.ProtocolsOverSsl detectSslProtocol(Integer srcPort, Integer dstPort) {
        Packet.ProtocolsOverSsl sslProtocol = Packet.ProtocolsOverSsl.UNKNOWN;
        if (srcPort == null || dstPort == null) {
            return sslProtocol;
        }
        if (srcPort == Packet.HTTPS_PORT || dstPort == Packet.HTTPS_PORT) {
            sslProtocol = Packet.ProtocolsOverSsl.HTTPS;
        } else if (srcPort == Packet.POP3_PORT_2 || dstPort == Packet.POP3_PORT_2) {
            sslProtocol = Packet.ProtocolsOverSsl.POP3;
        } else if(srcPort == Packet.IMAP_PORT_2 || dstPort == Packet.IMAP_PORT_2) {
            sslProtocol = Packet.ProtocolsOverSsl.IMAP;
        } else if (srcPort == Packet.SMTP_PORT_3 || dstPort == Packet.SMTP_PORT_3) {
            sslProtocol = Packet.ProtocolsOverSsl.SMTP;
        }
        return sslProtocol;
    }
}
