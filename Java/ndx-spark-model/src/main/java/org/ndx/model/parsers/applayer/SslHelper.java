package org.ndx.model.parsers.applayer;

import org.ndx.model.Packet;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public final class SslHelper {
    private static final int SSL3_CODE = 0x0300;
    private static final int TLS1_CODE = 0x0301;
    private static final int TLS11_CODE = 0x0302;
    private static final int TLS12_CODE = 0x0303;

    public static final String SSL3 = "SSL 3";
    public static final String TLS1 = "TLS 1";
    public static final String TLS11 = "TLS 1.1";
    public static final String TLS12 = "TLS 1.2";

    /**
     * Attempts to find out which application layer protocol
     * is encapsulated in ssl according to used ports.
     *
     * @param srcPort Source port.
     * @param dstPort Destination port.
     * @return Application layer protocol over ssl.
     */
    public static Packet.ProtocolsOverSsl detectSslProtocol(Integer srcPort, Integer dstPort) {
        Packet.ProtocolsOverSsl sslProtocol = Packet.ProtocolsOverSsl.UNKNOWN;
        if (srcPort == null || dstPort == null) {
            return sslProtocol;
        }
        if (srcPort == Packet.HTTPS_PORT || dstPort == Packet.HTTPS_PORT) {
            sslProtocol = Packet.ProtocolsOverSsl.HTTPS;
        } else if (srcPort == Packet.POP3_PORT_2 || dstPort == Packet.POP3_PORT_2) {
            sslProtocol = Packet.ProtocolsOverSsl.POP3;
        } else if (srcPort == Packet.IMAP_PORT_2 || dstPort == Packet.IMAP_PORT_2) {
            sslProtocol = Packet.ProtocolsOverSsl.IMAP;
        } else if (srcPort == Packet.SMTP_PORT_3 || dstPort == Packet.SMTP_PORT_3) {
            sslProtocol = Packet.ProtocolsOverSsl.SMTP;
        }
        return sslProtocol;
    }

    /**
     * @param date String representation of date.
     * @return Date.
     * @throws ParseException In case of not supported format.
     */
    public static Date parseDate(String date) throws ParseException {
        DateFormat format = new SimpleDateFormat("yy-MM-dd hh:mm:ss");
        return format.parse(date);
    }

    /**
     * @param hexVersion Ssl version in hexadecimal form.
     * @return String form of ssl version.
     */
    public static String decodeSslVersion(String hexVersion) {
        if (hexVersion == null) {
            return "";
        }

        int version;
        try {
            version = Integer.decode(hexVersion);
        } catch (Exception e) {
            return "";
        }

        switch (version) {
            case SSL3_CODE:
                return SSL3;
            case TLS1_CODE:
                return TLS1;
            case TLS11_CODE:
                return TLS11;
            case TLS12_CODE:
                return TLS12;
        }
        return "";
    }

    /**
     * @param decCs Cipher suite in decimal form.
     * @return String form of cipher suite.
     */
    public static String cipherSuiteDecToString(String decCs) {
        String cipherSuite;
        switch (decCs) {
            case "0":
                cipherSuite = "TLS_NULL_WITH_NULL_NULL";
                break;
            case "1":
                cipherSuite = "TLS_RSA_WITH_NULL_MD5";
                break;
            case "2":
                cipherSuite = "TLS_RSA_WITH_NULL_SHA";
                break;
            case "3":
                cipherSuite = "TLS_RSA_EXPORT_WITH_RC4_40_MD5";
                break;
            case "4":
                cipherSuite = "TLS_RSA_WITH_RC4_128_MD5";
                break;
            case "5":
                cipherSuite = "TLS_RSA_WITH_RC4_128_SHA";
                break;
            case "6":
                cipherSuite = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5";
                break;
            case "7":
                cipherSuite = "TLS_RSA_WITH_IDEA_CBC_SHA";
                break;
            case "8":
                cipherSuite = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA";
                break;
            case "9":
                cipherSuite = "TLS_RSA_WITH_DES_CBC_SHA";
                break;
            case "10":
                cipherSuite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "11":
                cipherSuite = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
                break;
            case "12":
                cipherSuite = "TLS_DH_DSS_WITH_DES_CBC_SHA";
                break;
            case "13":
                cipherSuite = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
                break;
            case "14":
                cipherSuite = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
                break;
            case "15":
                cipherSuite = "TLS_DH_RSA_WITH_DES_CBC_SHA";
                break;
            case "16":
                cipherSuite = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "17":
                cipherSuite = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
                break;
            case "18":
                cipherSuite = "TLS_DHE_DSS_WITH_DES_CBC_SHA";
                break;
            case "19":
                cipherSuite = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
                break;
            case "20":
                cipherSuite = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
                break;
            case "21":
                cipherSuite = "TLS_DHE_RSA_WITH_DES_CBC_SHA";
                break;
            case "22":
                cipherSuite = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "23":
                cipherSuite = "TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5";
                break;
            case "24":
                cipherSuite = "TLS_DH_Anon_WITH_RC4_128_MD5";
                break;
            case "25":
                cipherSuite = "TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA";
                break;
            case "26":
                cipherSuite = "TLS_DH_Anon_WITH_DES_CBC_SHA";
                break;
            case "27":
                cipherSuite = "TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA";
                break;
            case "28":
                cipherSuite = "SSL_FORTEZZA_KEA_WITH_NULL_SHA";
                break;
            case "29":
                cipherSuite = "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA";
                break;
            case "30":
                cipherSuite = "TLS_KRB5_WITH_DES_CBC_SHA";
                break;
            case "31":
                cipherSuite = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA";
                break;
            case "32":
                cipherSuite = "TLS_KRB5_WITH_RC4_128_SHA";
                break;
            case "33":
                cipherSuite = "TLS_KRB5_WITH_IDEA_CBC_SHA";
                break;
            case "34":
                cipherSuite = "TLS_KRB5_WITH_DES_CBC_MD5";
                break;
            case "35":
                cipherSuite = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5";
                break;
            case "36":
                cipherSuite = "TLS_KRB5_WITH_RC4_128_MD5";
                break;
            case "37":
                cipherSuite = "TLS_KRB5_WITH_IDEA_CBC_MD5";
                break;
            case "38":
                cipherSuite = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA";
                break;
            case "39":
                cipherSuite = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA";
                break;
            case "40":
                cipherSuite = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA";
                break;
            case "41":
                cipherSuite = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5";
                break;
            case "42":
                cipherSuite = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5";
                break;
            case "43":
                cipherSuite = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5";
                break;
            case "44":
                cipherSuite = "TLS_PSK_WITH_NULL_SHA";
                break;
            case "45":
                cipherSuite = "TLS_DHE_PSK_WITH_NULL_SHA";
                break;
            case "46":
                cipherSuite = "TLS_RSA_PSK_WITH_NULL_SHA";
                break;
            case "47":
                cipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA";
                break;
            case "48":
                cipherSuite = "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
                break;
            case "49":
                cipherSuite = "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
                break;
            case "50":
                cipherSuite = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
                break;
            case "51":
                cipherSuite = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
                break;
            case "52":
                cipherSuite = "TLS_DH_Anon_WITH_AES_128_CBC_SHA";
                break;
            case "53":
                cipherSuite = "TLS_RSA_WITH_AES_256_CBC_SHA";
                break;
            case "54":
                cipherSuite = "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
                break;
            case "55":
                cipherSuite = "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
                break;
            case "56":
                cipherSuite = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
                break;
            case "57":
                cipherSuite = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
                break;
            case "58":
                cipherSuite = "TLS_DH_Anon_WITH_AES_256_CBC_SHA";
                break;
            case "59":
                cipherSuite = "TLS_RSA_WITH_NULL_SHA256";
                break;
            case "60":
                cipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA256";
                break;
            case "61":
                cipherSuite = "TLS_RSA_WITH_AES_256_CBC_SHA256";
                break;
            case "62":
                cipherSuite = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
                break;
            case "63":
                cipherSuite = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
                break;
            case "64":
                cipherSuite = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
                break;
            case "65":
                cipherSuite = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA";
                break;
            case "66":
                cipherSuite = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA";
                break;
            case "67":
                cipherSuite = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA";
                break;
            case "68":
                cipherSuite = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA";
                break;
            case "69":
                cipherSuite = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
                break;
            case "70":
                cipherSuite = "TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA";
                break;
            case "71":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_NULL_SHA";
                break;
            case "72":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
                break;
            case "73":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA";
                break;
            case "74":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "75":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
                break;
            case "76":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
                break;
            case "96":
                cipherSuite = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5";
                break;
            case "97":
                cipherSuite = "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5";
                break;
            case "98":
                cipherSuite = "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA";
                break;
            case "99":
                cipherSuite = "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA";
                break;
            case "100":
                cipherSuite = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA";
                break;
            case "101":
                cipherSuite = "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA";
                break;
            case "102":
                cipherSuite = "TLS_DHE_DSS_WITH_RC4_128_SHA";
                break;
            case "103":
                cipherSuite = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
                break;
            case "104":
                cipherSuite = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
                break;
            case "105":
                cipherSuite = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
                break;
            case "106":
                cipherSuite = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
                break;
            case "107":
                cipherSuite = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
                break;
            case "108":
                cipherSuite = "TLS_DH_Anon_WITH_AES_128_CBC_SHA256";
                break;
            case "109":
                cipherSuite = "TLS_DH_Anon_WITH_AES_256_CBC_SHA256";
                break;
            case "128":
                cipherSuite = "TLS_GOSTR341094_WITH_28147_CNT_IMIT";
                break;
            case "129":
                cipherSuite = "TLS_GOSTR341001_WITH_28147_CNT_IMIT";
                break;
            case "130":
                cipherSuite = "TLS_GOSTR341094_WITH_NULL_GOSTR3411";
                break;
            case "131":
                cipherSuite = "TLS_GOSTR341001_WITH_NULL_GOSTR3411";
                break;
            case "132":
                cipherSuite = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA";
                break;
            case "133":
                cipherSuite = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA";
                break;
            case "134":
                cipherSuite = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA";
                break;
            case "135":
                cipherSuite = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA";
                break;
            case "136":
                cipherSuite = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
                break;
            case "137":
                cipherSuite = "TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA";
                break;
            case "138":
                cipherSuite = "TLS_PSK_WITH_RC4_128_SHA";
                break;
            case "139":
                cipherSuite = "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
                break;
            case "140":
                cipherSuite = "TLS_PSK_WITH_AES_128_CBC_SHA";
                break;
            case "141":
                cipherSuite = "TLS_PSK_WITH_AES_256_CBC_SHA";
                break;
            case "142":
                cipherSuite = "TLS_DHE_PSK_WITH_RC4_128_SHA";
                break;
            case "143":
                cipherSuite = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA";
                break;
            case "144":
                cipherSuite = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
                break;
            case "145":
                cipherSuite = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA";
                break;
            case "146":
                cipherSuite = "TLS_RSA_PSK_WITH_RC4_128_SHA";
                break;
            case "147":
                cipherSuite = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA";
                break;
            case "148":
                cipherSuite = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA";
                break;
            case "149":
                cipherSuite = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA";
                break;
            case "150":
                cipherSuite = "TLS_RSA_WITH_SEED_CBC_SHA";
                break;
            case "151":
                cipherSuite = "TLS_DH_DSS_WITH_SEED_CBC_SHA";
                break;
            case "152":
                cipherSuite = "TLS_DH_RSA_WITH_SEED_CBC_SHA";
                break;
            case "153":
                cipherSuite = "TLS_DHE_DSS_WITH_SEED_CBC_SHA";
                break;
            case "154":
                cipherSuite = "TLS_DHE_RSA_WITH_SEED_CBC_SHA";
                break;
            case "155":
                cipherSuite = "TLS_DH_Anon_WITH_SEED_CBC_SHA";
                break;
            case "156":
                cipherSuite = "TLS_RSA_WITH_AES_128_GCM_SHA256";
                break;
            case "157":
                cipherSuite = "TLS_RSA_WITH_AES_256_GCM_SHA384";
                break;
            case "158":
                cipherSuite = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
                break;
            case "159":
                cipherSuite = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
                break;
            case "160":
                cipherSuite = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
                break;
            case "161":
                cipherSuite = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
                break;
            case "162":
                cipherSuite = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
                break;
            case "163":
                cipherSuite = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
                break;
            case "164":
                cipherSuite = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
                break;
            case "165":
                cipherSuite = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
                break;
            case "166":
                cipherSuite = "TLS_DH_Anon_WITH_AES_128_GCM_SHA256";
                break;
            case "167":
                cipherSuite = "TLS_DH_Anon_WITH_AES_256_GCM_SHA384";
                break;
            case "168":
                cipherSuite = "TLS_PSK_WITH_AES_128_GCM_SHA256";
                break;
            case "169":
                cipherSuite = "TLS_PSK_WITH_AES_256_GCM_SHA384";
                break;
            case "170":
                cipherSuite = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
                break;
            case "171":
                cipherSuite = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
                break;
            case "172":
                cipherSuite = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
                break;
            case "173":
                cipherSuite = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384";
                break;
            case "174":
                cipherSuite = "TLS_PSK_WITH_AES_128_CBC_SHA256";
                break;
            case "175":
                cipherSuite = "TLS_PSK_WITH_AES_256_CBC_SHA384";
                break;
            case "176":
                cipherSuite = "TLS_PSK_WITH_NULL_SHA256";
                break;
            case "177":
                cipherSuite = "TLS_PSK_WITH_NULL_SHA384";
                break;
            case "178":
                cipherSuite = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
                break;
            case "179":
                cipherSuite = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
                break;
            case "180":
                cipherSuite = "TLS_DHE_PSK_WITH_NULL_SHA256";
                break;
            case "181":
                cipherSuite = "TLS_DHE_PSK_WITH_NULL_SHA384";
                break;
            case "182":
                cipherSuite = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256";
                break;
            case "183":
                cipherSuite = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384";
                break;
            case "184":
                cipherSuite = "TLS_RSA_PSK_WITH_NULL_SHA256";
                break;
            case "185":
                cipherSuite = "TLS_RSA_PSK_WITH_NULL_SHA384";
                break;
            case "49153":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_NULL_SHA";
                break;
            case "49154":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
                break;
            case "49155":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49156":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
                break;
            case "49157":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
                break;
            case "49158":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
                break;
            case "49159":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
                break;
            case "49160":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49161":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
                break;
            case "49162":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
                break;
            case "49163":
                cipherSuite = "TLS_ECDH_RSA_WITH_NULL_SHA";
                break;
            case "49164":
                cipherSuite = "TLS_ECDH_RSA_WITH_RC4_128_SHA";
                break;
            case "49165":
                cipherSuite = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49166":
                cipherSuite = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
                break;
            case "49167":
                cipherSuite = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
                break;
            case "49168":
                cipherSuite = "TLS_ECDHE_RSA_WITH_NULL_SHA";
                break;
            case "49169":
                cipherSuite = "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
                break;
            case "49170":
                cipherSuite = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49171":
                cipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
                break;
            case "49172":
                cipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
                break;
            case "49173":
                cipherSuite = "TLS_ECDH_Anon_WITH_NULL_SHA";
                break;
            case "49174":
                cipherSuite = "TLS_ECDH_Anon_WITH_RC4_128_SHA";
                break;
            case "49175":
                cipherSuite = "TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49176":
                cipherSuite = "TLS_ECDH_Anon_WITH_AES_128_CBC_SHA";
                break;
            case "49177":
                cipherSuite = "TLS_ECDH_Anon_WITH_AES_256_CBC_SHA";
                break;
            case "49178":
                cipherSuite = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49179":
                cipherSuite = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49180":
                cipherSuite = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49181":
                cipherSuite = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA";
                break;
            case "49182":
                cipherSuite = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
                break;
            case "49183":
                cipherSuite = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
                break;
            case "49184":
                cipherSuite = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA";
                break;
            case "49185":
                cipherSuite = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
                break;
            case "49186":
                cipherSuite = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";
                break;
            case "49187":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
                break;
            case "49188":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
                break;
            case "49189":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
                break;
            case "49190":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
                break;
            case "49191":
                cipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
                break;
            case "49192":
                cipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
                break;
            case "49193":
                cipherSuite = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
                break;
            case "49194":
                cipherSuite = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
                break;
            case "49195":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
                break;
            case "49196":
                cipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
                break;
            case "49197":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
                break;
            case "49198":
                cipherSuite = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
                break;
            case "49199":
                cipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
                break;
            case "49200":
                cipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
                break;
            case "49201":
                cipherSuite = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
                break;
            case "49202":
                cipherSuite = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
                break;
            case "49203":
                cipherSuite = "TLS_ECDHE_PSK_WITH_RC4_128_SHA";
                break;
            case "49204":
                cipherSuite = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA";
                break;
            case "49205":
                cipherSuite = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
                break;
            case "49206":
                cipherSuite = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA";
                break;
            case "49207":
                cipherSuite = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
                break;
            case "49208":
                cipherSuite = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
                break;
            case "49209":
                cipherSuite = "TLS_ECDHE_PSK_WITH_NULL_SHA";
                break;
            case "49210":
                cipherSuite = "TLS_ECDHE_PSK_WITH_NULL_SHA256";
                break;
            case "49211":
                cipherSuite = "TLS_ECDHE_PSK_WITH_NULL_SHA384";
                break;
            case "65278":
                cipherSuite = "SSL_RSA_FIPS_WITH_DES_CBC_SHA";
                break;
            case "65279":
                cipherSuite = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA";
                break;
            case "65504":
                cipherSuite = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA";
                break;
            case "65505":
                cipherSuite = "SSL_RSA_FIPS_WITH_DES_CBC_SHA";
                break;
            case "65664":
                cipherSuite = "SSL2_RC4_128_WITH_MD5";
                break;
            case "131200":
                cipherSuite = "SSL2_RC4_128_EXPORT40_WITH_MD5";
                break;
            case "196736":
                cipherSuite = "SSL2_RC2_CBC_128_CBC_WITH_MD5";
                break;
            case "262272":
                cipherSuite = "SSL2_RC2_CBC_128_CBC_WITH_MD5";
                break;
            case "327808":
                cipherSuite = "SSL2_IDEA_128_CBC_WITH_MD5";
                break;
            case "393280":
                cipherSuite = "SSL2_DES_64_CBC_WITH_MD5";
                break;
            case "458944":
                cipherSuite = "SSL2_DES_192_EDE3_CBC_WITH_MD5";
                break;
            case "524416":
                cipherSuite = "SSL2_RC4_64_WITH_MD5";
                break;
            case "8388609":
                cipherSuite = "PCT_SSL_CERT_TYPE";
                break;
            case "8388611":
                cipherSuite = "PCT_SSL_CERT_TYPE";
                break;
            case "8454145":
                cipherSuite = "PCT_SSL_HASH_TYPE";
                break;
            case "8454147":
                cipherSuite = "PCT_SSL_HASH_TYPE";
                break;
            case "8519681":
                cipherSuite = "PCT_SSL_EXCH_TYPE";
                break;
            case "8585220":
                cipherSuite = "PCT_SSL_CIPHER_TYPE_1ST_HALF";
                break;
            case "8661056":
                cipherSuite = "PCT_SSL_CIPHER_TYPE_2ND_HALF";
                break;
            case "8683584":
                cipherSuite = "PCT_SSL_CIPHER_TYPE_2ND_HALF";
                break;
            case "9404417":
                cipherSuite = "PCT_SSL_COMPAT";
                break;
            default:
                cipherSuite = decCs;
        }
        return cipherSuite;
    }

}
