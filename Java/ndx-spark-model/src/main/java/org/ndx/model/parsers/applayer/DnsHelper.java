package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public final class DnsHelper {
    protected static final Log LOG = LogFactory.getLog(DnsHelper.class);

    public static String idToType (String id) throws NumberFormatException {
        String type;
        int typeId = Integer.decode(id);
        switch (typeId) {
            case 1: type = "A"; break;
            case 2: type = "NS"; break;
            case 3: type = "MD"; break;
            case 4: type = "MF"; break;
            case 5: type = "CNAME"; break;
            case 6: type = "SOA"; break;
            case 7: type = "MB"; break;
            case 8: type = "MG"; break;
            case 9: type = "MR"; break;
            case 10: type = "NULL"; break;
            case 11: type = "WKS"; break;
            case 12: type = "PTR"; break;
            case 13: type = "HINFO"; break;
            case 14: type = "MINFO"; break;
            case 15: type = "MX"; break;
            case 16: type = "TXT"; break;
            case 17: type = "RP"; break;
            case 18: type = "AFSDB"; break;
            case 19: type = "X25"; break;
            case 20: type = "ISDN"; break;
            case 21: type = "RT"; break;
            case 22: type = "NSAP"; break;
            case 23: type = "NSAP-PTR"; break;
            case 24: type = "NSAP-PTR"; break;
            case 25: type = "KEY"; break;
            case 26: type = "PX"; break;
            case 27: type = "GPOS"; break;
            case 28: type = "AAAA"; break;
            case 29: type = "LOC"; break;
            case 30: type = "NXT"; break;
            case 31: type = "EID"; break;
            case 32: type = "NIMLOC"; break;
            case 33: type = "SRV"; break;
            case 34: type = "ATMA"; break;
            case 35: type = "NAPTR"; break;
            case 36: type = "KX"; break;
            case 37: type = "CERT"; break;
            case 38: type = "A6"; break;
            case 39: type = "DNAME"; break;
            case 40: type = "SINK"; break;
            case 41: type = "OPT"; break;
            case 42: type = "APL"; break;
            case 43: type = "DS"; break;
            case 44: type = "SSHFP"; break;
            case 45: type = "IPSECKEY"; break;
            case 46: type = "RRSIG"; break;
            case 47: type = "NSEC"; break;
            case 48: type = "DNSKEY"; break;
            case 49: type = "DHCID"; break;
            case 50: type = "NSEC3"; break;
            case 51: type = "NSEC3PARAM"; break;
            case 52: type = "TLSA"; break;
            case 53: type = "SMIMEA"; break;
            case 55: type = "HIP"; break;
            case 56: type = "NINFO"; break;
            case 57: type = "RKEY"; break;
            case 58: type = "TALINK"; break;
            case 59: type = "CDS"; break;
            case 60: type = "CDNSKEY"; break;
            case 61: type = "OPENPGPKEY"; break;
            case 62: type = "CSYNC"; break;
            case 99: type = "SPF"; break;
            case 100: type = "UINFO"; break;
            case 101: type = "UID"; break;
            case 102: type = "GID"; break;
            case 103: type = "UNSPEC"; break;
            case 104: type = "NID"; break;
            case 105: type = "L32"; break;
            case 106: type = "L64"; break;
            case 107: type = "LP"; break;
            case 108: type = "EUI48"; break;
            case 109: type = "EUI64"; break;
            case 249: type = "TKEY"; break;
            case 250: type = "TSIG"; break;
            case 251: type = "IXFR"; break;
            case 252: type = "AXFR"; break;
            case 253: type = "MAILB"; break;
            case 254: type = "MAILA"; break;
            case 255: type = "ANY"; break;
            case 256: type = "URI"; break;
            case 257: type = "CAA"; break;
            case 258: type = "AVC"; break;
            case 259: type = "DOA"; break;
            case 32768: type = "TA"; break;
            case 32769: type = "DLV"; break;
            default:
                throw new NumberFormatException("DNS Resource Record type with id=" + id + " does not exist.");
        }
        return type;
    }

    public static String idToClass (String id) {
        String type;
        int typeId = Integer.decode(id);
        switch (typeId) {
            case 1: type = "IN"; break;
            case 3: type = "CH"; break;
            case 4: type = "HS"; break;
            case 254: type = "NONE"; break;
            case 255: type = "ANY"; break;
            default:
                throw new NumberFormatException("DNS class with id=" + id + " does not exist.");
        }
        return type;
    }

    public static String formatOutput(String name,  String type, String cls) {
        return formatOutput(name, type, cls, "");
    }

    public static String formatOutput(String name, String type, String cls, String rdata) {
        String output = "";
        try {
            output = name + "," + DnsHelper.idToType(type) + "," + DnsHelper.idToClass(cls);
            if (rdata != null && !rdata.isEmpty()) {
                output += "," + rdata;
            }
        } catch (NumberFormatException e) {
            LOG.warn("Malformed DNS packet: " + e.getMessage());
        }
        return output;
    }

}
