package org.ndx.model.json;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;

import java.util.HashMap;

public class JsonHelper {
    private static final Log LOG = LogFactory.getLog(Packet.class);

    public static void addBoolValue(HashMap<String, Object> map, String key, String value) {
        if (value == null) {
            LOG.warn("Missing value - " + key);
            return;
        }
        if ("0".equals(value)) {
            map.put(key, false);
        } else if ("1".equals(value)) {
            map.put(key, true);
        } else {
            LOG.warn("Invalid value - " + key);
        }
    }

    public static void addStringValue(HashMap<String, Object> map, String key, String value) {
        if (value != null) {
            map.put(key, value);
            return;
        }
        LOG.warn("Missing value - " + key);
    }

    public static void addLongValue(HashMap<String, Object> map, String key, String value) {
        if (value == null) {
            LOG.warn("Missing value - " + key);
            return;
        }
        try {
            map.put(key, Long.decode(value));
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + key);
        }
    }

    public static void addIntValue(HashMap<String, Object> map, String key, String value) {
        if (value == null) {
            LOG.warn("Missing value - " + key);
            return;
        }
        try {
            map.put(key, Integer.decode(value));
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + key);
        }
    }

}
