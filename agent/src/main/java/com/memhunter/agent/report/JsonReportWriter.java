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

    public void write(ScanReport report, String filePath) throws IOException {
        File out = new File(filePath);
        File parent = out.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        mapper.writeValue(out, report);
    }
}
