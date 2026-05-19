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

        Path out = tmp.resolve("report.json");
        new JsonReportWriter().write(r, out.toString());

        String content = new String(Files.readAllBytes(out));
        assertTrue(content.contains("\"scanId\""));
        assertTrue(content.contains("scan-test-001"));
        assertTrue(content.contains("finding-class-filter-aaaabbbb"));
        assertTrue(content.contains("com.example.Abc"));
    }
}
