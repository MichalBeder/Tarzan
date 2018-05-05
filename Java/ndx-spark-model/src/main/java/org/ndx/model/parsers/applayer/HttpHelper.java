package org.ndx.model.parsers.applayer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public final class HttpHelper {
    private static final Log LOG = LogFactory.getLog(HttpHelper.class);

    /**
     * Parses domain name from URL.
     *
     * @param url URL with these prefixes: http://, https://, http://www., https://www., www.
     * @return The domain name.
     */
    public static String getHostFromUrl(String url) {
        try {
            String host = url.replaceFirst("^(http[s]?://www\\.|http[s]?://|www\\.)", "").split("/")[0];
            return host == null ? "" : host;
        } catch (Exception e) {
            LOG.warn("Malformed url - " + url);
            return "";
        }
    }

}
