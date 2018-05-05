package org.ndx.pcap;

public class PcapReaderUtil {

    public static long convertInt(byte[] data) {
        return convertInt(data, false);
    }

    public static long convertInt(byte[] data, boolean reversed) {
        if (!reversed) {
            return ((data[3] & 0xFF) << 24) | ((data[2] & 0xFF) << 16)
                    | ((data[1] & 0xFF) << 8) | (data[0] & 0xFF);
        } else {
            return ((data[0] & 0xFF) << 24) | ((data[1] & 0xFF) << 16)
                    | ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        }
    }

    public static long convertInt(byte[] data, int offset, boolean reversed) {
        byte[] target = new byte[4];
        System.arraycopy(data, offset, target, 0, target.length);
        return convertInt(target, reversed);
    }

}
