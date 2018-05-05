package org.ndx.model.json;

import java.util.ArrayList;

public interface JsonAdapter {
    long getLongValue(String key);

    int getIntValue(String key);

    boolean getBoolValue(String key);

    String getStringValue(String key);

    ArrayList<String> getStringArray(String key);

    ArrayList<JsonAdapter> getLayersArray(String key);

    boolean isArray(String key);

    boolean isString(String key);

    boolean containsKey(String key);

    JsonAdapter getLayer(String key);
}
