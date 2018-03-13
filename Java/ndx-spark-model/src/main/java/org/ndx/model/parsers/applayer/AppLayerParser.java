package org.ndx.model.parsers.applayer;

import java.util.HashMap;
import java.util.Map;

public abstract class AppLayerParser extends HashMap<String, Object> {
    public abstract void parse(byte[] payload);
    public abstract void parse(Map<String, Object> payload);
}
