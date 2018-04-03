package org.ndx.model.pcap;

import org.apache.commons.codec.binary.Hex;
import org.ndx.model.Packet;
import org.ndx.model.parsers.applayer.*;
import org.ndx.model.pcap.PacketModel.RawFrame;

import java.util.function.Consumer;

public class PcapPacket extends Packet {

    private static final long UNIX_BASE_TICKS = 621355968000000000L;
    private static final long TICKS_PER_MILLISECOND = 10000L;
    
    private static final int ETHERNET_HEADER_SIZE = 14;
    private static final int ETHERNET_TYPE_OFFSET = 12;
    private static final int ETHERNET_TYPE_IP = 0x800;
    private static final int ETHERNET_TYPE_IPV6 = 0x86dd;
    private static final int ETHERNET_TYPE_8021Q = 0x8100;
    private static final int SLL_HEADER_BASE_SIZE = 10; // SLL stands for Linux cooked-mode capture
    private static final int SLL_ADDRESS_LENGTH_OFFSET = 4; // relative to SLL header
    private static final int IPV6_HEADER_SIZE = 40;
    private static final int IP_VHL_OFFSET = 0;	// relative to start of IP header
    private static final int IP_TTL_OFFSET = 8;	// relative to start of IP header
    private static final int IP_TOTAL_LEN_OFFSET = 2;	// relative to start of IP header
    private static final int IPV6_PAYLOAD_LEN_OFFSET = 4; // relative to start of IP header
    private static final int IPV6_HOPLIMIT_OFFSET = 7; // relative to start of IP header
    private static final int IP_PROTOCOL_OFFSET = 9;	// relative to start of IP header
    private static final int IPV6_NEXTHEADER_OFFSET = 6; // relative to start of IP header
    private static final int IP_SRC_OFFSET = 12;	// relative to start of IP header
    private static final int IPV6_SRC_OFFSET = 8; // relative to start of IP header
    private static final int IP_DST_OFFSET = 16;	// relative to start of IP header
    private static final int IPV6_DST_OFFSET = 24; // relative to start of IP header
    private static final int IP_ID_OFFSET = 4;	// relative to start of IP header
    private static final int IPV6_ID_OFFSET = 4;	// relative to start of IP header
    private static final int IP_FLAGS_OFFSET = 6;	// relative to start of IP header
    private static final int IPV6_FLAGS_OFFSET = 3;	// relative to start of IP header
    private static final int IP_FRAGMENT_OFFSET = 6;	// relative to start of IP header
    private static final int IPV6_FRAGMENT_OFFSET = 2;	// relative to start of IP header
    private static final int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
    private static final int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;
    private static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
    private static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
    private static final int TCP_HEADER_DATA_OFFSET = 12;

    /**
     * Attempts to parse the input RawFrame into Packet.
     * @param frame An input frame to be parsed.
     */
    @Override
    public void parsePacket(RawFrame frame) {
        parsePacket(frame, this::processTcpUdpPayload);
    }

    public void parsePacket(RawFrame frame, Consumer<PacketPayload> processPayload) {
        byte[] packetData = frame.getData().toByteArray();
        int snapLen = 65535;

        put(FRAME_LENGTH, frame.getFrameLength());
        put(TIMESTAMP, convertTimeStamp(frame.getTimeStamp()));
        put(NUMBER, frame.getFrameNumber());

        int ipStart = findIPStart(frame.getLinkTypeValue(), packetData);
        if (ipStart == -1)
            return;

        int ipProtocolHeaderVersion = getInternetProtocolHeaderVersion(packetData, ipStart);
        put(IP_VERSION, ipProtocolHeaderVersion);

        if (ipProtocolHeaderVersion == 4 || ipProtocolHeaderVersion == 6) {
            int ipHeaderLen = getInternetProtocolHeaderLength(packetData, ipProtocolHeaderVersion, ipStart);
            int totalLength;
            if (ipProtocolHeaderVersion == 4) {
                buildInternetProtocolV4Packet(packetData, ipStart);
                totalLength = BitConverter.convertShort(packetData, ipStart + IP_TOTAL_LEN_OFFSET);
            } else {
                buildInternetProtocolV6Packet(packetData, ipStart);
                ipHeaderLen += buildInternetProtocolV6ExtensionHeaderFragment(packetData, ipStart);
                int payloadLength = BitConverter.convertShort(packetData, ipStart + IPV6_PAYLOAD_LEN_OFFSET);
                totalLength = payloadLength + IPV6_HEADER_SIZE;
            }
            put(IP_HEADER_LENGTH, ipHeaderLen);

            if ((Boolean) get(FRAGMENT)) {
                LOG.info("IP fragment detected - fragmented packets are not supported.");
            } else {
                String protocol = (String) get(PROTOCOL);
                int payloadDataStart = ipStart + ipHeaderLen;
                int payloadLength = totalLength - ipHeaderLen;
                byte[] packetPayload = readPayload(packetData, payloadDataStart, payloadLength, snapLen);
                if (PROTOCOL_UDP.equals(protocol) || PROTOCOL_TCP.equals(protocol)) {
                    packetPayload = buildTcpAndUdpPacket(packetData, ipProtocolHeaderVersion, ipStart,
                            ipHeaderLen, totalLength, snapLen);
                }
                if (PROTOCOL_TCP.equals(protocol))
                    this.put(HEX_PAYLOAD, packetPayload != null ? Hex.encodeHexString(packetPayload) : "");
                put(LEN, packetPayload != null ? packetPayload.length : 0);
                processPacketPayload(packetPayload, processPayload);
            }
        }
    }

    private void processTcpUdpPayload(PacketPayload p) {
        byte[] payload = p.getPayload();
        if (payload == null || payload.length == 0) {
            put(Packet.APP_LAYER_PROTOCOL, AppLayerProtocols.UNKNOWN);
            return;
        }
        if (tryParseDnsProtocol(payload)) return;
        if (tryParseEmailProtocol()) return;
        if (tryParseHttpProtocol(payload)) return;
        if (detectHttpsProtocol()) return; // TODO replace with ssl parser and detect there
        put(Packet.APP_LAYER_PROTOCOL, AppLayerProtocols.UNKNOWN);
    }

    private boolean detectHttpsProtocol() {
        Integer src = (Integer) get(SRC_PORT);
        Integer dst = (Integer) get(DST_PORT);
        if (src != null && dst != null && (src == 443 || dst == 443)) {
            put(Packet.APP_LAYER_PROTOCOL, AppLayerProtocols.SSL);
            put(Packet.PROTOCOL_OVER_SSL, Packet.ProtocolsOverSsl.HTTPS);
            return true;
        }
        return false;
    }

    private boolean tryParseHttpProtocol(byte[] payload) {
        HttpPcapParser httpParser = new HttpPcapParser();
        try {
            httpParser.parse(payload);
        } catch (IllegalArgumentException e) {
            return false;
        }
        put(Packet.APP_LAYER_PROTOCOL, AppLayerProtocols.HTTP);
        putAll(httpParser);
        return true;
    }

    private boolean tryParseEmailProtocol() {
        Integer src = (Integer) get(SRC_PORT);
        Integer dst = (Integer) get(DST_PORT);
        if (src == null || dst == null) {
            return false;
        }

        AppLayerProtocols protocol = AppLayerProtocols.UNKNOWN;
        if (src == POP3_PORT_1 || dst == POP3_PORT_1 || src == POP3_PORT_2 || dst == POP3_PORT_2) {
            protocol = AppLayerProtocols.POP3;
        } else if (src == IMAP_PORT_1 || dst == IMAP_PORT_1 || src == IMAP_PORT_2 || dst == IMAP_PORT_2) {
            protocol = AppLayerProtocols.IMAP;
        } else if (src == SMTP_PORT_1 || dst == SMTP_PORT_1 || src == SMTP_PORT_2 || dst == SMTP_PORT_2
                || src == SMTP_PORT_3 || dst == SMTP_PORT_3) {
            protocol = AppLayerProtocols.SMTP;
        }

        if (protocol == AppLayerProtocols.UNKNOWN) {
            return false;
        }
        put(Packet.APP_LAYER_PROTOCOL, protocol);
        return true;
    }

    private boolean tryParseDnsProtocol(byte[] payload) {
        Integer src = (Integer) get(SRC_PORT);
        Integer dst = (Integer) get(DST_PORT);
        if (src != null && dst != null && (src == 53 || dst == 53)) {
            try {
                DnsPcapParser dnsParser = new DnsPcapParser();
                dnsParser.parse(payload);
                put(Packet.APP_LAYER_PROTOCOL, AppLayerProtocols.DNS);
                putAll(dnsParser);
                return true;
            } catch (IllegalArgumentException e) {
                LOG.warn("Malformed DNS packet.");
                return false;
            }
        }
        return false;
    }

    private long convertTimeStamp(long timeStamp) {
        return (timeStamp - UNIX_BASE_TICKS) / TICKS_PER_MILLISECOND;
    }

    /**
     * This method call function for further processing the content of TCP or UDP segment.
     * @param payload 			payload of the packet, it is the content of UDP or TCP segment
     * @param processPayload	function that is called for processing the content. It can be null.
     */
    private void processPacketPayload(byte[] payload, Consumer<PacketPayload> processPayload) {
        if (processPayload != null) {
            processPayload.accept(new PacketPayload(this, payload));
        }
    }

    private int findIPStart(int linkType, byte[] packet) {
        int start;
        switch (linkType) {
            case Constants.DataLinkType.Null_VALUE:
                return 4;
            case Constants.DataLinkType.Ethernet_VALUE:
                start = ETHERNET_HEADER_SIZE;
                int etherType = BitConverter.convertShort(packet, ETHERNET_TYPE_OFFSET);
                if (etherType == ETHERNET_TYPE_8021Q) {
                    etherType = BitConverter.convertShort(packet, ETHERNET_TYPE_OFFSET + 4);
                    start += 4;
                }
                if (etherType == ETHERNET_TYPE_IP || etherType == ETHERNET_TYPE_IPV6)
                    return start;
                break;
            case Constants.DataLinkType.Raw_VALUE:
                return 0;
            case Constants.DataLinkType.Loop_VALUE:
                return 4;
            case Constants.DataLinkType.LinuxSLL_VALUE:
                start = SLL_HEADER_BASE_SIZE;
                int sllAddressLength = BitConverter.convertShort(packet, SLL_ADDRESS_LENGTH_OFFSET);
                start += sllAddressLength;
                return start;
        }
        return -1;
    }

    private int getInternetProtocolHeaderLength(byte[] packet, int ipProtocolHeaderVersion, int ipStart) {
        if (ipProtocolHeaderVersion == 4)
            return (packet[ipStart + IP_VHL_OFFSET] & 0xF) * 4;
        else if (ipProtocolHeaderVersion == 6)
            return 40;
        return -1;
    }

    private int getInternetProtocolHeaderVersion(byte[] packet, int ipStart) {
        return (packet[ipStart + IP_VHL_OFFSET] >> 4) & 0xF;
    }

    private int getTcpHeaderLength(byte[] packet, int tcpStart) {
        int dataOffset = tcpStart + TCP_HEADER_DATA_OFFSET;
        return ((packet[dataOffset] >> 4) & 0xF) * 4;
    }

    private void buildInternetProtocolV4Packet(byte[] packetData, int ipStart) {
        long id = (long) BitConverter.convertShort(packetData, ipStart + IP_ID_OFFSET);
        put(ID, id);

        int flags = packetData[ipStart + IP_FLAGS_OFFSET] & 0xE0;
        put(IP_FLAGS_DF, (flags & 0x40) != 0);
        put(IP_FLAGS_MF, (flags & 0x20) != 0);

        long fragmentOffset = (BitConverter.convertShort(packetData, ipStart + IP_FRAGMENT_OFFSET) & 0x1FFF) * 8;
        put(FRAGMENT_OFFSET, fragmentOffset);

        if ((flags & 0x20) != 0 || fragmentOffset != 0) {
            put(FRAGMENT, true);
            put(LAST_FRAGMENT, ((flags & 0x20) == 0 && fragmentOffset != 0));
        } else {
            put(FRAGMENT, false);
        }

        int ttl = packetData[ipStart + IP_TTL_OFFSET] & 0xFF;
        put(TTL, ttl);

        int protocol = packetData[ipStart + IP_PROTOCOL_OFFSET];
        put(PROTOCOL, convertProtocolIdentifier(protocol));

        String src = BitConverter.convertAddress(packetData, ipStart + IP_SRC_OFFSET, 4);
        put(SRC, src);

        String dst = BitConverter.convertAddress(packetData, ipStart + IP_DST_OFFSET, 4);
        put(DST, dst);
    }

    private void buildInternetProtocolV6Packet(byte[] packetData, int ipStart) {
        int ttl = packetData[ipStart + IPV6_HOPLIMIT_OFFSET] & 0xFF;
        put(TTL, ttl);

        int protocol = packetData[ipStart + IPV6_NEXTHEADER_OFFSET];
        put(PROTOCOL, convertProtocolIdentifier(protocol));

        String src = BitConverter.convertAddress(packetData, ipStart + IPV6_SRC_OFFSET, 16);
        put(SRC, src);

        String dst = BitConverter.convertAddress(packetData, ipStart + IPV6_DST_OFFSET, 16);
        put(DST, dst);
    }

    private int buildInternetProtocolV6ExtensionHeaderFragment(byte[] packetData, int ipStart) {
        if (PROTOCOL_FRAGMENT.equals(get(PROTOCOL))) {
            long id = BitConverter.convertUnsignedInt(packetData, ipStart + IPV6_HEADER_SIZE + IPV6_ID_OFFSET);
            put(ID, id);

            int flags = packetData[ipStart + IPV6_HEADER_SIZE + IPV6_FLAGS_OFFSET] & 0x7;
            put(IPV6_FLAGS_M, (flags & 0x1) != 0);

            long fragmentOffset = BitConverter.convertShort(packetData, ipStart + IPV6_HEADER_SIZE +
                    IPV6_FRAGMENT_OFFSET) & 0xFFF8;
            put(FRAGMENT_OFFSET, fragmentOffset);

            put(FRAGMENT, true);
            put(LAST_FRAGMENT, ((flags & 0x1) == 0 && fragmentOffset != 0));

            int protocol = packetData[ipStart + IPV6_HEADER_SIZE];
            put(PROTOCOL, convertProtocolIdentifier(protocol)); // Change protocol to value from fragment header

            return 8; // Return fragment header extension length
        }

        // Not a fragment
        put(FRAGMENT, false);
        return 0;
    }

    /*
     * packetData is the entire layer 2 packet read from pcap
     * ipStart is the start of the IP packet in packetData
     */
    private byte[] buildTcpAndUdpPacket(byte[] packetData, int ipProtocolHeaderVersion, int ipStart,
                                        int ipHeaderLen, int totalLength, int snapLen) {
        this.put(SRC_PORT, BitConverter.convertShort(packetData,
                ipStart + ipHeaderLen + PROTOCOL_HEADER_SRC_PORT_OFFSET));
        this.put(DST_PORT, BitConverter.convertShort(packetData,
                ipStart + ipHeaderLen + PROTOCOL_HEADER_DST_PORT_OFFSET));

        int tcpOrUdpHeaderSize;
        final String protocol = (String)this.get(PROTOCOL);
        if (PROTOCOL_UDP.equals(protocol)) {
            tcpOrUdpHeaderSize = UDP_HEADER_SIZE;

            if (ipProtocolHeaderVersion == 4) {
                int cksum = getUdpChecksum(packetData, ipStart, ipHeaderLen);
                if (cksum >= 0)
                    this.put(UDPSUM, cksum);
            }
            // TODO UDP Checksum for IPv6 packets
            int udpLen = getUdpLength(packetData, ipStart, ipHeaderLen);
            this.put(UDP_LENGTH, udpLen);
            this.put(PAYLOAD_LEN, udpLen);
        } else if (PROTOCOL_TCP.equals(protocol)) {
            tcpOrUdpHeaderSize = getTcpHeaderLength(packetData, ipStart + ipHeaderLen);
            this.put(TCP_HEADER_LENGTH, tcpOrUdpHeaderSize);

            // Store the sequence and acknowledgement numbers --M
            this.put(TCP_SEQ, BitConverter.convertUnsignedInt(packetData, ipStart + ipHeaderLen +
                    PROTOCOL_HEADER_TCP_SEQ_OFFSET));
            this.put(TCP_ACK, BitConverter.convertUnsignedInt(packetData, ipStart + ipHeaderLen +
                    PROTOCOL_HEADER_TCP_ACK_OFFSET));

            // Flags stretch two bytes starting at the TCP header offset
            int flags = BitConverter.convertShort(new byte[] { packetData[ipStart + ipHeaderLen +
                    TCP_HEADER_DATA_OFFSET], packetData[ipStart + ipHeaderLen + TCP_HEADER_DATA_OFFSET + 1] })
                    & 0x1FF; // Filter first 7 bits. First 4 are the data offset and the other 3 reserved for future use.
            this.put(TCP_FLAG_NS, (flags & 0x100) != 0);
            this.put(TCP_FLAG_CWR, (flags & 0x80) != 0);
            this.put(TCP_FLAG_ECE, (flags & 0x40) != 0);
            this.put(TCP_FLAG_URG, (flags & 0x20) != 0);
            this.put(TCP_FLAG_ACK, (flags & 0x10) != 0);
            this.put(TCP_FLAG_PSH, (flags & 0x8) != 0);
            this.put(TCP_FLAG_RST, (flags & 0x4) != 0);
            this.put(TCP_FLAG_SYN, (flags & 0x2) != 0);
            this.put(TCP_FLAG_FIN, (flags & 0x1) != 0);
            // The TCP payload size is calculated by taking the "Total Length" from the IP header (ip.len)
            // and then substract the "IP header length" (ip.hdr_len) and the "TCP header length" (tcp.hdr_len).
            int tcpLen = totalLength-(tcpOrUdpHeaderSize + ipHeaderLen);
            this.put(PAYLOAD_LEN, tcpLen);
        } else {
            return null;
        }

        int payloadDataStart = ipStart + ipHeaderLen + tcpOrUdpHeaderSize;
        int payloadLength = totalLength - ipHeaderLen - tcpOrUdpHeaderSize;
        return readPayload(packetData, payloadDataStart, payloadLength, snapLen);
    }

    private int getUdpChecksum(byte[] packetData, int ipStart, int ipHeaderLen) {
        /*
         * No Checksum on this packet?
         */
        if (packetData[ipStart + ipHeaderLen + 6] == 0 &&
            packetData[ipStart + ipHeaderLen + 7] == 0)
            return -1;

        /*
         * Build data[] that we can checksum.  Its a pseudo-header
         * followed by the entire UDP packet.
         */
        byte data[] = new byte[packetData.length - ipStart - ipHeaderLen + 12];
        int sum = 0;
        System.arraycopy(packetData, ipStart + IP_SRC_OFFSET, data, 0, 4);
        System.arraycopy(packetData, ipStart + IP_DST_OFFSET, data, 4, 4);
        data[8] = 0;
        data[9] = 17;	/* IPPROTO_UDP */
        System.arraycopy(packetData, ipStart + ipHeaderLen + 4, data, 10, 2);
        System.arraycopy(packetData, ipStart + ipHeaderLen, data, 12,
                packetData.length - ipStart - ipHeaderLen);
        for (int i = 0; i<data.length; i++) {
            int j = data[i];
            if (j < 0)
                j += 256;
            sum += j << (i % 2 == 0 ? 8 : 0);
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (~sum) & 0xffff;
    }

    private int getUdpLength(byte[] packetData, int ipStart, int ipHeaderLen) {
        return BitConverter.convertShort(packetData, ipStart + ipHeaderLen + 4);
    }
    
    private byte[] readPayload(byte[] packetData, int payloadDataStart, int payloadLength, int snapLen) {
        if (payloadLength < 0) {
            LOG.warn("Malformed packet - negative payload length. Returning empty payload.");
            return new byte[0];
        }
        if (payloadDataStart > packetData.length) {
            LOG.warn("Payload start (" + payloadDataStart + ") is larger than packet data (" +
                    packetData.length + "). Returning empty payload.");
            return new byte[0];
        }
        if (payloadDataStart + payloadLength > packetData.length) {
            if (payloadDataStart + payloadLength <= snapLen) // Only corrupted if it was not because of a reduced snap length
                LOG.warn("Payload length field value (" + payloadLength + ") is larger than available packet data ("
                        + (packetData.length - payloadDataStart)
                        + "). Packet may be corrupted. Returning only available data.");
            payloadLength = packetData.length - payloadDataStart;
        }
        byte[] data = new byte[payloadLength];
        System.arraycopy(packetData, payloadDataStart, data, 0, payloadLength);
        return data;
    }
}
