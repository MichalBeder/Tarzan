package org.ndx.model;

import java.util.HashMap;

public class DnsParser implements AppLayerParser {

    public static final String COUNT_QUERIES = "dns_dns_count_queries";
    public static final String COUNT_ANSWERS = "dns_dns_count_answers";
    public static final String COUNT_AUTH = "dns_dns_count_auth_rr";
    public static final String COUNT_ADD = "dns_dns_count_add_rr";
    public static final String QUERY_OR_RESPONSE = "dns_flags_dns_flags_response";
    public static final String DNS_ID = "dns_dns_id";
    public static final String DNS_RECORD = "text_text";

    @Override
    public HashMap<String, Object> parseJson() {

        return null;
    }

    @Override
    public HashMap<String, Object> parsePcap() {
        return null;
    }
}
