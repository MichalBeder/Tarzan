package org.ndx.model.json;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.Collectors;

public class JsonSfParser implements JsonAdapter {

    private JSONObject jsonObject;

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

    private JsonSfParser(JSONObject json) {
        jsonObject = json;
    }

    public JsonAdapter getLayer(String key) {
        try {
            JSONObject temp = jsonObject.getJSONObject(key);
            return new JsonSfParser(temp);
        } catch(JSONException e) {
            throw new IllegalArgumentException("Missing " + key + " layer", e);
        }
    }

    public int getIntValue(String key) {
        return (int) getValue(x -> Integer.decode((String)jsonObject.get(x)), key);
    }

    public long getLongValue(String key) {
        return (long) getValue(x -> Long.decode((String)jsonObject.get(x)), key);
    }

    public boolean getBoolValue(String key) {
        return (boolean) getValue(x -> {
            String val = (String)jsonObject.get(x);
            if ("0".equals(val)) {
                return false;
            } else if ("1".equals(val)) {
                return true;
            } else throw new IllegalArgumentException();}
            , key);
    }

    public String getStringValue(String key) {
        return (String) getValue(x -> jsonObject.getString(x), key);
    }

    public ArrayList<String> getStringArray(String key) {
        try {
            return Arrays.stream(jsonObject.getJSONArray(key).toArray())
                    .filter(x -> x instanceof String)
                    .map (x -> (String) x)
                    .collect(Collectors.toCollection(ArrayList::new));
        } catch (JSONException e) {
            throw new IllegalArgumentException("Missing string array values - " + key, e);
        }
    }

    public ArrayList<JsonAdapter> getLayersArray(String key) {
        try {
            return Arrays.stream(jsonObject.getJSONArray(key).toArray())
                    .filter(x -> x instanceof JSONObject)
                    .map (x -> new JsonSfParser((JSONObject) x))
                    .collect(Collectors.toCollection(ArrayList::new));
        } catch (JSONException e) {
            throw new IllegalArgumentException("Missing adapter array values - " + key, e);
        }
    }

    public boolean isArray(String key) {
        try {
            jsonObject.getJSONArray(key);
            return true;
        } catch (JSONException e) {
            return false;
        }
    }

    public boolean isString(String key) {
        try {
            return jsonObject.get(key) instanceof String;
        } catch (JSONException e) {
            return false;
        }
    }

    public boolean containsKey(String key) {
        return jsonObject.containsKey(key);
    }

    private Object getValue(Function<String, Object> func, String key) {
        try {
            return func.apply(key);
        } catch(Exception e) {
            throw new IllegalArgumentException("Missing value - " + key, e);
        }
    }

}
