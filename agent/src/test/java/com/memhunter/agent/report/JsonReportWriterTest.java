package com.memhunter.agent.report;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonReportWriterTest {

    @Test
    void writes_json_file_with_expected_fields(@TempDir Path tmp) throws IOException {
        ScanReport r = new ScanReport();
        r.scanId = "scan-test-001";
        Finding f = new Finding();
        f.id = "finding-class-filter-aaaabbbb";
        f.type = "class-filter";
        f.className = "com.example.Abc";
        r.findings.add(f);
        r.summary.totalFindings = 1;
        r.summary.baselineNewCount = 1;
        r.summary.baselineMatchedCount = 2;

        Path out = tmp.resolve("report.json");
        new JsonReportWriter().write(r, out.toString());

        String content = new String(Files.readAllBytes(out));
        assertTrue(content.contains("\"scanId\""));
        assertTrue(content.contains("scan-test-001"));
        assertTrue(content.contains("finding-class-filter-aaaabbbb"));
        assertTrue(content.contains("com.example.Abc"));
        assertTrue(content.contains("\"baselineNewCount\""));
        assertTrue(content.contains("\"baselineMatchedCount\""));
    }

    @org.junit.jupiter.api.Test
    void writes_atomically_overwriting_existing_file(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp) throws java.io.IOException {
        // Pre-create the target file with garbage content
        java.nio.file.Path out = tmp.resolve("report.json");
        java.nio.file.Files.write(out, "OLD_CONTENT".getBytes());

        ScanReport r = new ScanReport();
        r.scanId = "scan-atomic-001";
        r.summary.totalFindings = 0;

        new JsonReportWriter().write(r, out.toString());

        String content = new String(java.nio.file.Files.readAllBytes(out));
        org.junit.jupiter.api.Assertions.assertTrue(content.contains("scan-atomic-001"),
                "Expected new content, got: " + content);
        org.junit.jupiter.api.Assertions.assertFalse(content.contains("OLD_CONTENT"));

        // No leftover .tmp file
        java.nio.file.Path leftover = tmp.resolve("report.json.tmp");
        org.junit.jupiter.api.Assertions.assertFalse(java.nio.file.Files.exists(leftover),
                "Leftover .tmp file should not exist");
    }
}
