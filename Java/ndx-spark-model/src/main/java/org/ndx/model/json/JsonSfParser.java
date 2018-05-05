package org.ndx.model.json;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.Collectors;


public class JsonSfParser implements JsonAdapter {

    private JSONObject jsonObject;

    /**
     * Validates the input json string.
     *
     * @param json Input in json format
     */
    JsonSfParser(String json) {
        String msg = "Malformed JSON packet.";
        try {
            jsonObject = JSONObject.fromObject(json);
        } catch (Exception e) {
            throw new IllegalArgumentException(msg, e);
        }
        if (jsonObject.isNullObject()) {
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Private constructor that allows returning new layers.
     *
     * @param json The new layer.
     */
    private JsonSfParser(JSONObject json) {
        jsonObject = json;
    }

    /**
     * Attempts to return layer associated with key.
     *
     * @param key Key associated with the desired layer.
     * @return Layer associated with key.
     */
    public JsonAdapter getLayer(String key) {
        try {
            JSONObject temp = jsonObject.getJSONObject(key);
            return new JsonSfParser(temp);
        } catch (JSONException e) {
            throw new IllegalArgumentException("Missing " + key + " layer", e);
        }
    }

    /**
     * Attempts to return integer value associated with key.
     *
     * @param key Key associated with the desired value.
     * @return Integer value associated with key.
     */
    public int getIntValue(String key) {
        return (int) getValue(x -> Integer.decode((String) jsonObject.get(x)), key);
    }

    /**
     * Attempts to return long value associated with key.
     *
     * @param key Key associated with the desired value.
     * @return Long value associated with key.
     */
    public long getLongValue(String key) {
        return (long) getValue(x -> Long.decode((String) jsonObject.get(x)), key);
    }

    /**
     * Attempts to return boolean value associated with key.
     *
     * @param key Key associated with the desired value.
     * @return Boolean value associated with key.
     */
    public boolean getBoolValue(String key) {
        return (boolean) getValue(x -> {
                    String val = (String) jsonObject.get(x);
                    if ("0".equals(val)) {
                        return false;
                    } else if ("1".equals(val)) {
                        return true;
                    } else throw new IllegalArgumentException();
                }
                , key);
    }

    /**
     * Attempts to return string value associated with key.
     *
     * @param key Key associated with the desired value.
     * @return String value associated with key.
     */
    public String getStringValue(String key) {
        return (String) getValue(x -> jsonObject.getString(x), key);
    }

    /**
     * Attempts to return array of strings associated with key.
     *
     * @param key Key associated with the desired array.
     * @return Array associated with key.
     */
    public ArrayList<String> getStringArray(String key) {
        try {
            return Arrays.stream(jsonObject.getJSONArray(key).toArray())
                    .filter(x -> x instanceof String)
                    .map(x -> (String) x)
                    .collect(Collectors.toCollection(ArrayList::new));
        } catch (JSONException e) {
            throw new IllegalArgumentException("Missing string array values - " + key, e);
        }
    }

    /**
     * Attempts to return json layer of strings associated with key.
     *
     * @param key Key associated with the desired json layer.
     * @return Json layer associated with key.
     */
    public ArrayList<JsonAdapter> getLayersArray(String key) {
        try {
            return Arrays.stream(jsonObject.getJSONArray(key).toArray())
                    .filter(x -> x instanceof JSONObject)
                    .map(x -> new JsonSfParser((JSONObject) x))
                    .collect(Collectors.toCollection(ArrayList::new));
        } catch (JSONException e) {
            throw new IllegalArgumentException("Missing adapter array values - " + key, e);
        }
    }

    /**
     * @param key Key associated with desired array.
     * @return True if the value associated with key is an array.
     */
    public boolean isArray(String key) {
        try {
            jsonObject.getJSONArray(key);
            return true;
        } catch (JSONException e) {
            return false;
        }
    }

    /**
     * @param key Key associated with desired string value.
     * @return True if the value associated with key is a string.
     */
    public boolean isString(String key) {
        try {
            return jsonObject.get(key) instanceof String;
        } catch (JSONException e) {
            return false;
        }
    }

    /**
     * @param key Key to be checked.
     * @return True if the current json layer contains given key.
     */
    public boolean containsKey(String key) {
        return jsonObject.containsKey(key);
    }

    /**
     * @param func Function to be applied.
     * @param key  Parameter of the function.
     * @return Result of the function.
     */
    private Object getValue(Function<String, Object> func, String key) {
        try {
            return func.apply(key);
        } catch (Exception e) {
            throw new IllegalArgumentException("Missing value - " + key, e);
        }
    }

}
