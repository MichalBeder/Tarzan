package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public final class HttpHelper {
    private static final Log LOG = LogFactory.getLog(HttpHelper.class);

    public static String getHostfromUrl(String url) {
        try {
            String host = url.replaceFirst("^(http[s]?://www\\.|http[s]?://|www\\.)","").split("/")[0];
            return host == null? "" : host;
        } catch (Exception e) {
            LOG.warn("Malformed url - " + url);
            return "";
        }
    }
}
