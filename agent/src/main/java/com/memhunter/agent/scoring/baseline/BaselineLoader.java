package com.memhunter.agent.scoring.baseline;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

/**
 * Reads a previous ScanReport JSON file and extracts all finding IDs into a BaselineIndex.
 * Returns an empty index on any failure (IO, parse, malformed JSON).
 */
public final class BaselineLoader {

    private BaselineLoader() {}

    public static BaselineIndex load(String path) {
        if (path == null) return BaselineIndex.empty();
        File f = new File(path);
        if (!f.exists()) return BaselineIndex.empty();
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(f);
            JsonNode findings = root.get("findings");
            if (findings == null || !findings.isArray()) return BaselineIndex.empty();
            Set<String> ids = new HashSet<>();
            for (JsonNode finding : findings) {
                JsonNode id = finding.get("id");
                if (id != null && id.isTextual()) ids.add(id.asText());
            }
            return new BaselineIndex(ids);
        } catch (Throwable t) {
            return BaselineIndex.empty();
        }
    }
}
