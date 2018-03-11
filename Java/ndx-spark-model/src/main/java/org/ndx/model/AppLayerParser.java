package org.ndx.model;

import java.util.HashMap;

public interface AppLayerParser {
    HashMap<String, Object> parseJson();
    HashMap<String, Object> parsePcap();
}
