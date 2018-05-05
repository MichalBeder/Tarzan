package org.ndx.model.pcap;

public class PacketPayload {
    private PcapPacket _packet;
    private byte[] _payload;

    public PacketPayload(PcapPacket packet, byte[] payload) {
        _packet = packet;
        _payload = payload;
    }

    public PcapPacket getPacket() {
        return _packet;
    }

    public byte[] getPayload() {
        return _payload;
    }

}
