package org.ndx.model;

import java.util.HashMap;
import java.util.Map;

import io.kaitai.struct.ByteBufferKaitaiStream;
import org.ndx.model.FlowModel.FlowKey;
import org.ndx.model.PacketModel.RawFrame;
import java.util.function.Consumer;
import com.google.protobuf.ByteString;

public class PcapPacket extends Packet {
//    protected static final long serialVersionUID = 8723206921174160146L;

    private static long UNIX_BASE_TICKS = 621355968000000000L;
    private static long TICKS_PER_MILLISECOND = 10000L;
    
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

    public static FlowModel.FlowKey flowKeyParse(String flowkey) {
        String[] parts = flowkey.split("\\[|@|:|->|\\]");
        FlowKey.Builder fb = FlowKey.newBuilder();
        fb.setProtocol(ByteString.copyFromUtf8(parts[1]));
        fb.setSourceAddress(ByteString.copyFromUtf8(parts[2]));
        fb.setSourceSelector(ByteString.copyFromUtf8(parts[3]));
        fb.setDestinationAddress(ByteString.copyFromUtf8(parts[4]));
        fb.setDestinationSelector(ByteString.copyFromUtf8(parts[5]));
        return fb.build();
    }

    /**
     * Returns FlowKey for the current Packet.
     * @return FlowKey for the current Packet.
     */
    public FlowModel.FlowKey getFlowKey() {
        FlowModel.FlowKey.Builder fb = FlowModel.FlowKey.newBuilder();
        fb.setProtocol(ByteString.copyFromUtf8(get(PROTOCOL).toString()));
        fb.setSourceAddress(ByteString.copyFromUtf8(get(SRC).toString() ));
        fb.setSourceSelector(ByteString.copyFromUtf8(get(SRC_PORT).toString() ));
        fb.setDestinationAddress(ByteString.copyFromUtf8(get(DST).toString() ));
        fb.setDestinationSelector(ByteString.copyFromUtf8(get(DST_PORT).toString() ));
        return fb.build();
    }

    public String getSessionString() {
        String loAddress;
        String hiAddress;
        Integer loPort;
        Integer hiPort;
        if (((String)get(SRC)).compareTo((String)get(DST)) == 0) {
            loAddress = (String)get(SRC);
            hiAddress = (String)get(DST);
            if ((Integer)get(SRC_PORT) < (Integer)get(DST_PORT)) {
                loPort = (Integer)get(SRC_PORT);
                hiPort = (Integer)get(DST_PORT);
            } else {
                loPort = (Integer)get(DST_PORT);
                hiPort = (Integer)get(SRC_PORT);
            }
        }
        else if (((String)get(SRC)).compareTo((String)get(DST)) < 0) {
            loAddress = (String)get(SRC);
            loPort = (Integer)get(SRC_PORT);
            hiAddress = (String)get(DST);
            hiPort = (Integer)get(DST_PORT);
        } else {
            loAddress = (String)get(DST);
            loPort = (Integer)get(DST_PORT);
            hiAddress = (String)get(SRC);
            hiPort = (Integer)get(SRC_PORT);
        }

        return "[" +
                this.get(PROTOCOL) +
                "@" +
                loAddress +
                ":" +
                loPort +
                "<->" +
                hiAddress +
                ":" +
                hiPort +
                "]";
    }

    /**
     * Extends the collection of attributes of the current Packet with the provided colleciton.
     *
     * @param prefix The prefix to be used when adding attributes. If null then no prefix will be used.
     * @param source The source collection of the attributes. It can be null.
     */
    public void extendWith(String prefix, HashMap<String,Object> source) {
        if (source == null) return;
        for (Map.Entry<String,Object> entry : source.entrySet()) {
            this.put(prefix == null ? entry.getKey() : prefix + "." + entry.getKey(), entry.getValue());
        }
    }

    /**
     * Attempts to parse the input RawFrame into Packet.
     * @param frame An input frame to be parsed.
     * @return a Packet object for the given input RawFrame.
     */
    public static PcapPacket parsePacket(RawFrame frame)
    {
        return parsePacket(frame, null);
    }

    public static PcapPacket parsePacket(RawFrame frame, Consumer<PacketPayload> processPayload) {
        return parsePacket(frame.getLinkTypeValue(), getTimeStamp(frame), frame.getFrameNumber(),
                frame.getData().toByteArray(), 65535, processPayload);
    }

    public static PcapPacket parsePacket(int linkType, long timestamp, int number, byte[] packetData,
                                         int snapLen, Consumer<PacketPayload> processPayload) {
        PcapPacket packet = new PcapPacket();
        packet.put(TIMESTAMP, timestamp);
        packet.put(NUMBER, number);

        int ipStart = findIPStart(linkType, packetData);
        if (ipStart == -1)
            return packet;

        int ipProtocolHeaderVersion = getInternetProtocolHeaderVersion(packetData, ipStart);
        packet.put(IP_VERSION, ipProtocolHeaderVersion);

        if (ipProtocolHeaderVersion == 4 || ipProtocolHeaderVersion == 6) {
            int ipHeaderLen = getInternetProtocolHeaderLength(packetData, ipProtocolHeaderVersion, ipStart);
            int totalLength = 0;
            if (ipProtocolHeaderVersion == 4) {
                buildInternetProtocolV4Packet(packet, packetData, ipStart);
                totalLength = BitConverter.convertShort(packetData, ipStart + IP_TOTAL_LEN_OFFSET);
            } else if (ipProtocolHeaderVersion == 6) {
                buildInternetProtocolV6Packet(packet, packetData, ipStart);
                ipHeaderLen += buildInternetProtocolV6ExtensionHeaderFragment(packet, packetData, ipStart);
                int payloadLength = BitConverter.convertShort(packetData, ipStart + IPV6_PAYLOAD_LEN_OFFSET);
                totalLength = payloadLength + IPV6_HEADER_SIZE;
            }
            packet.put(IP_HEADER_LENGTH, ipHeaderLen);

            if ((Boolean)packet.get(FRAGMENT)) {
                LOG.info("IP fragment detected - fragmented packets are not supported.");
            } else {
                String protocol = (String)packet.get(PROTOCOL);
                int payloadDataStart = ipStart + ipHeaderLen;
                int payloadLength = totalLength - ipHeaderLen;
                byte[] packetPayload = packet.readPayload(packetData, payloadDataStart, payloadLength, snapLen);
                if (PROTOCOL_UDP.equals(protocol) || PROTOCOL_TCP.equals(protocol)) {
                    packetPayload = packet.buildTcpAndUdpPacket(packetData, ipProtocolHeaderVersion, ipStart,
                            ipHeaderLen, totalLength, snapLen);
                }

                packet.put(LEN, packetPayload != null ? packetPayload.length : 0);
//                packet.processPacketPayload(packetPayload, processPayload);
                packet.processPacketPayload(packetPayload);
            }
        }
        return packet;
    }


    //TODO delete this testing function
    @Override
    public String getDnsAnswCnt() {
        if (this.get(DNS_ANSWER_CNT) != null) {
            return this.get(DNS_ANSWER_CNT).toString();
        }
        return "";
    }

    private void processPacketPayload(byte[] payload) {
        if (PROTOCOL_UDP.equals(get(PROTOCOL)) && (53 == (int)get(SRC_PORT) || 53 == (int)get(DST_PORT))) {
            DnsPacket data = new DnsPacket(new ByteBufferKaitaiStream(payload));
            this.put(DNS_ANSWER_CNT, data.ancount());
        }
    }

    private static long getTimeStamp(RawFrame frame) {
        long timeStamp = frame.getTimeStamp();
        return (timeStamp - UNIX_BASE_TICKS) / TICKS_PER_MILLISECOND;
    }

    /**
     * This method call function for further processing the content of TCP or UDP segment.
     * @param payload 			payload of the packet, it is the content of UDP or TCP segment
     * @param processPayload	function that is called for processing the content. It can be null.
     */
    private void processPacketPayload(byte[] payload, Consumer<PacketPayload> processPayload) {
        if (processPayload != null)
        {
            processPayload.accept(new PacketPayload(this, payload));
        }
    }

    private static int findIPStart(int linkType, byte[] packet) {
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

    private static int getInternetProtocolHeaderLength(byte[] packet, int ipProtocolHeaderVersion, int ipStart) {
        if (ipProtocolHeaderVersion == 4)
            return (packet[ipStart + IP_VHL_OFFSET] & 0xF) * 4;
        else if (ipProtocolHeaderVersion == 6)
            return 40;
        return -1;
    }

    private static int getInternetProtocolHeaderVersion(byte[] packet, int ipStart) {
        return (packet[ipStart + IP_VHL_OFFSET] >> 4) & 0xF;
    }

    private static int getTcpHeaderLength(byte[] packet, int tcpStart) {
        int dataOffset = tcpStart + TCP_HEADER_DATA_OFFSET;
        return ((packet[dataOffset] >> 4) & 0xF) * 4;
    }

    private static void buildInternetProtocolV4Packet(PcapPacket packet, byte[] packetData, int ipStart) {
        long id = (long) BitConverter.convertShort(packetData, ipStart + IP_ID_OFFSET);
        packet.put(ID, id);

        int flags = packetData[ipStart + IP_FLAGS_OFFSET] & 0xE0;
        packet.put(IP_FLAGS_DF, (flags & 0x40) != 0);
        packet.put(IP_FLAGS_MF, (flags & 0x20) != 0);

        long fragmentOffset = (BitConverter.convertShort(packetData, ipStart + IP_FRAGMENT_OFFSET) & 0x1FFF) * 8;
        packet.put(FRAGMENT_OFFSET, fragmentOffset);

        if ((flags & 0x20) != 0 || fragmentOffset != 0) {
            packet.put(FRAGMENT, true);
            packet.put(LAST_FRAGMENT, ((flags & 0x20) == 0 && fragmentOffset != 0));
        } else {
            packet.put(FRAGMENT, false);
        }

        int ttl = packetData[ipStart + IP_TTL_OFFSET] & 0xFF;
        packet.put(TTL, ttl);

        int protocol = packetData[ipStart + IP_PROTOCOL_OFFSET];
        packet.put(PROTOCOL, convertProtocolIdentifier(protocol));

        String src = BitConverter.convertAddress(packetData, ipStart + IP_SRC_OFFSET, 4);
        packet.put(SRC, src);

        String dst = BitConverter.convertAddress(packetData, ipStart + IP_DST_OFFSET, 4);
        packet.put(DST, dst);
    }

    private static void buildInternetProtocolV6Packet(PcapPacket packet, byte[] packetData, int ipStart) {
        int ttl = packetData[ipStart + IPV6_HOPLIMIT_OFFSET] & 0xFF;
        packet.put(TTL, ttl);

        int protocol = packetData[ipStart + IPV6_NEXTHEADER_OFFSET];
        packet.put(PROTOCOL, convertProtocolIdentifier(protocol));

        String src = BitConverter.convertAddress(packetData, ipStart + IPV6_SRC_OFFSET, 16);
        packet.put(SRC, src);

        String dst = BitConverter.convertAddress(packetData, ipStart + IPV6_DST_OFFSET, 16);
        packet.put(DST, dst);
    }

    private static int buildInternetProtocolV6ExtensionHeaderFragment(PcapPacket packet, byte[] packetData,
                                                                      int ipStart) {
        if (PROTOCOL_FRAGMENT.equals(packet.get(PROTOCOL))) {
            long id = BitConverter.convertUnsignedInt(packetData, ipStart + IPV6_HEADER_SIZE + IPV6_ID_OFFSET);
            packet.put(ID, id);

            int flags = packetData[ipStart + IPV6_HEADER_SIZE + IPV6_FLAGS_OFFSET] & 0x7;
            packet.put(IPV6_FLAGS_M, (flags & 0x1) != 0);

            long fragmentOffset = BitConverter.convertShort(packetData, ipStart + IPV6_HEADER_SIZE +
                    IPV6_FRAGMENT_OFFSET) & 0xFFF8;
            packet.put(FRAGMENT_OFFSET, fragmentOffset);

            packet.put(FRAGMENT, true);
            packet.put(LAST_FRAGMENT, ((flags & 0x1) == 0 && fragmentOffset != 0));

            int protocol = packetData[ipStart + IPV6_HEADER_SIZE];
            packet.put(PROTOCOL, convertProtocolIdentifier(protocol)); // Change protocol to value from fragment header

            return 8; // Return fragment header extension length
        }

        // Not a fragment
        packet.put(FRAGMENT, false);
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
