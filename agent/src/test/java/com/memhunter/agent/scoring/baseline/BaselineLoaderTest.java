package com.memhunter.agent.scoring.baseline;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class BaselineLoaderTest {

    @Test
    void loads_finding_ids_from_valid_scan_report(@TempDir Path tmp) throws IOException {
        Path baseline = tmp.resolve("baseline.json");
        Files.write(baseline, ("{"
                + "\"scanId\":\"scan-test\","
                + "\"findings\":["
                + "  {\"id\":\"finding-class-filter-aaaabbbb\",\"type\":\"class-filter\"},"
                + "  {\"id\":\"finding-tomcat-filter-ccccdddd\",\"type\":\"tomcat-filter\"}"
                + "]"
                + "}").getBytes());

        BaselineIndex idx = BaselineLoader.load(baseline.toString());
        assertEquals(2, idx.size());
        assertTrue(idx.contains("finding-class-filter-aaaabbbb"));
        assertTrue(idx.contains("finding-tomcat-filter-ccccdddd"));
    }

    @Test
    void returns_empty_for_nonexistent_file(@TempDir Path tmp) {
        Path nonexistent = tmp.resolve("nope.json");
        BaselineIndex idx = BaselineLoader.load(nonexistent.toString());
        assertTrue(idx.isEmpty());
    }

    @Test
    void returns_empty_for_null_path() {
        BaselineIndex idx = BaselineLoader.load(null);
        assertTrue(idx.isEmpty());
    }

    @Test
    void returns_empty_for_malformed_json(@TempDir Path tmp) throws IOException {
        Path baseline = tmp.resolve("bad.json");
        Files.write(baseline, "this is not json at all".getBytes());
        BaselineIndex idx = BaselineLoader.load(baseline.toString());
        assertTrue(idx.isEmpty());
    }

    @Test
    void returns_empty_for_missing_findings_array(@TempDir Path tmp) throws IOException {
        Path baseline = tmp.resolve("noarray.json");
        Files.write(baseline, "{\"scanId\":\"scan-test\"}".getBytes());
        BaselineIndex idx = BaselineLoader.load(baseline.toString());
        assertTrue(idx.isEmpty());
    }
}
