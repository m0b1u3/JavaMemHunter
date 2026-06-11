package com.memhunter.attach;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.memhunter.agent.model.OperationStatus;

import java.io.File;

/**
 * Reads the agent-written {@link OperationStatus} from a status file path. Returns null when the
 * file is missing or unreadable, so the caller can fall back to legacy "loaded successfully"
 * behaviour for older agents that do not write status (v1.2 backward compatibility).
 */
public final class StatusFileReader {

    private StatusFileReader() {}

    public static OperationStatus read(String path) {
        if (path == null || path.trim().isEmpty()) return null;
        File f = new File(path);
        if (!f.isFile() || f.length() == 0) return null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            return mapper.readValue(f, OperationStatus.class);
        } catch (Throwable t) {
            return null;
        }
    }
}
