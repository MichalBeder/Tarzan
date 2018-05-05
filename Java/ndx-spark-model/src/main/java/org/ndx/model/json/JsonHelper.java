package org.ndx.model.json;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ndx.model.Packet;

import java.util.Map;


public final class JsonHelper {
    private static final Log LOG = LogFactory.getLog(Packet.class);

    public enum ValueTypes {
        INT,
        LONG,
        STRING,
        BOOLEAN,
    }

    public static void addValue(Integer packetNumber, Map<String, Object> map, String mapKey, JsonAdapter json,
                                String jsonKey, ValueTypes type) {
        addValue(packetNumber, map, mapKey, json, jsonKey, type, true);
    }

    /**
     * Gets value from json, then puts this value with mapKey to the map.
     *
     * @param packetNumber Packet identifier for logging purposes.
     * @param map          map.add(mapKey, json.get(jsonKey))
     * @param mapKey       Key to be added to map.
     * @param json         Json source.
     * @param jsonKey      Key associated with the desired value from json.
     * @param type         Type of the desired value from json.
     */
    public static void addValue(Integer packetNumber, Map<String, Object> map, String mapKey, JsonAdapter json,
                                String jsonKey, ValueTypes type, boolean warn) {
        try {
            switch (type) {
                case INT:
                    map.put(mapKey, json.getIntValue(jsonKey));
                    break;
                case LONG:
                    map.put(mapKey, json.getLongValue(jsonKey));
                    break;
                case STRING:
                    map.put(mapKey, json.getStringValue(jsonKey));
                    break;
                case BOOLEAN:
                    map.put(mapKey, json.getBoolValue(jsonKey));
                    break;
                default:
            }
        } catch (IllegalArgumentException e) {
            if (warn) {
                LOG.warn(Packet.getLogPrefix(packetNumber) + e.getMessage());
            }
        }
    }

}
