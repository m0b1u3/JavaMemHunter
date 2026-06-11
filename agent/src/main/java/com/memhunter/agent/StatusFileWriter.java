package com.memhunter.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.memhunter.agent.model.OperationStatus;

import java.io.File;

/**
 * Best-effort writer of {@link OperationStatus} to the attach-supplied status file path.
 * Writing status must NEVER fail the underlying operation, so all errors are swallowed.
 */
public final class StatusFileWriter {

    private StatusFileWriter() {}

    public static void write(String path, OperationStatus status) {
        if (path == null || path.trim().isEmpty() || status == null) return;
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            File f = new File(path);
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            mapper.writeValue(f, status);
        } catch (Throwable ignored) {
            // intentional: status reporting is best-effort
        }
    }
}
