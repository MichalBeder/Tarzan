package org.ndx.model.json;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class JsonHelper {
    private static final Log LOG = LogFactory.getLog(Packet.class);

    public static boolean getBoolValue(String key, Object value) {
        return getBoolValue(key, value, false);
    }

    public static boolean getBoolValue(String key, Object value, boolean defaultValue) {
        if (value == null || !(value instanceof String)) {
            LOG.warn("Missing value - " + key);
            return defaultValue;
        }
        if ("0".equals(value)) {
            return false;
        } else if ("1".equals(value)) {
            return true;
        } else {
            LOG.warn("Invalid value - " + key);
            return defaultValue;
        }
    }

    public static String getStringValue(String key, Object value) {
        if (value == null || !(value instanceof String)) {
            LOG.warn("Missing value - " + key);
            return "";
        }
        String result = (String) value;
        if (result.isEmpty()) {
            LOG.warn("Missing value - " + key);
        }
        return result;
    }

    public static long getLongValue(String key, Object value) {
        return getLongValue(key, value, -1);
    }

    public static long getLongValue(String key, Object value, long defaultValue) {
        if (value == null || !(value instanceof String)) {
            LOG.warn("Missing value - " + key);
            return defaultValue;
        }
        long result = defaultValue;
        try {
            result = Long.decode((String) value);
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + key);
        }
        return result;
    }

    public static int getIntValue(String key, Object value) {
        return getIntValue(key, value, -1);
    }

    public static int getIntValue(String key, Object value, int defaultValue) {
        if (value == null || !(value instanceof String)) {
            LOG.warn("Missing value - " + key);
            return defaultValue;
        }
        int result = defaultValue;
        try {
            result = Integer.decode((String) value);
        } catch (NumberFormatException e) {
            LOG.warn("Missing value - " + key);
        }
        return result;
    }

    public static String castString(Map<String, Object> map, String key) {
        return map.get(key) instanceof String ? (String) map.get(key) : "";
    }

    @SuppressWarnings("unchecked")
    public static ArrayList<String> castStringArray(Map<String, Object> map, String key) {
        return map.get(key) instanceof ArrayList ? (ArrayList<String>) map.get(key) : null;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> castHashMap(Map<String, Object> map, String key) {
        return map.get(key) instanceof Map ? (Map<String, Object>) map.get(key) : null;
    }

}
