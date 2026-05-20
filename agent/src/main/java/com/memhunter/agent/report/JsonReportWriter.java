package com.memhunter.agent.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.memhunter.agent.model.ScanReport;

import java.io.File;
import java.io.IOException;

public class JsonReportWriter {

    private final ObjectMapper mapper;

    public JsonReportWriter() {
        this.mapper = new ObjectMapper();
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    /**
     * Writes the report atomically by serializing to a {@code <path>.tmp} sibling file,
     * then renaming it onto the final path. Prevents partially-written reports when the
     * agent is interrupted or the JVM is killed mid-flush.
     *
     * On Windows {@code renameTo} cannot replace an existing file, so we delete-then-rename
     * if the destination exists. Best-effort cleanup of the temp file on failure.
     */
    public void write(ScanReport report, String filePath) throws IOException {
        File finalFile = new File(filePath);
        File parent = finalFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        File tempFile = new File(filePath + ".tmp");
        mapper.writeValue(tempFile, report);
        if (finalFile.exists() && !finalFile.delete()) {
            tempFile.delete();
            throw new IOException("Cannot delete existing report file: " + finalFile);
        }
        if (!tempFile.renameTo(finalFile)) {
            tempFile.delete();
            throw new IOException("Atomic rename failed: " + tempFile + " -> " + finalFile);
        }
    }
}
