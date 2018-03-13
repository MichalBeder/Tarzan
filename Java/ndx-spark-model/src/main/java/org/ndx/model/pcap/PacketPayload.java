package org.ndx.model.pcap;

public class PacketPayload {
    PcapPacket _packet;
    byte[] _payload;
    public PacketPayload(PcapPacket packet, byte[] payload)
    {
        _packet = packet;
        _payload = payload;
    }

    public PcapPacket getPacket()
    {
        return _packet;
    }
    public byte[] getPayload()
    {
        return _payload;
    }
}