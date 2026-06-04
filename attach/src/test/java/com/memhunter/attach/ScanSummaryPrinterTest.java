package com.memhunter.attach;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ScanSummaryPrinterTest {

    @TempDir
    Path tempDir;

    private String capture(String reportPath, int pid) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ScanSummaryPrinter.print(new PrintStream(bos, true, "UTF-8"), reportPath, pid);
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    private Path writeReport(String json) throws Exception {
        Path p = tempDir.resolve("scan.json");
        Files.write(p, json.getBytes(StandardCharsets.UTF_8));
        return p;
    }

    @Test
    void prints_counts_and_lists_critical_high_suspicious_not_low() throws Exception {
        String json = "{"
                + "\"target\":{\"pid\":19440},"
                + "\"summary\":{\"critical\":2,\"high\":1,\"suspicious\":1,\"low\":3},"
                + "\"findings\":["
                + "{\"level\":\"critical\",\"type\":\"tomcat-filter\",\"className\":\"org.apache.coyote.ser.SerializerCache\",\"score\":16},"
                + "{\"level\":\"critical\",\"type\":\"tomcat-filter\",\"className\":\"org.apache.coyote.util.StdDateFormat\",\"score\":16},"
                + "{\"level\":\"high\",\"type\":\"class-servlet\",\"className\":\"org.apache.jsp.shell_jsp\",\"score\":7},"
                + "{\"level\":\"suspicious\",\"type\":\"tomcat-servlet\",\"className\":\"com.x.Foo\",\"score\":5},"
                + "{\"level\":\"low\",\"type\":\"tomcat-servlet\",\"className\":\"com.benign.LowOne\",\"score\":0},"
                + "{\"level\":\"low\",\"type\":\"tomcat-servlet\",\"className\":\"com.benign.LowTwo\",\"score\":0},"
                + "{\"level\":\"low\",\"type\":\"tomcat-servlet\",\"className\":\"com.benign.LowThree\",\"score\":0}"
                + "]}";
        Path p = writeReport(json);
        String out = capture(p.toString(), 19440);
        assertTrue(out.contains("critical: 2") && out.contains("high: 1")
                && out.contains("suspicious: 1") && out.contains("low: 3"), out);
        assertTrue(out.contains("org.apache.coyote.ser.SerializerCache"), out);
        assertTrue(out.contains("org.apache.coyote.util.StdDateFormat"), out);
        assertTrue(out.contains("org.apache.jsp.shell_jsp"), out);
        assertTrue(out.contains("com.x.Foo"), out);
        assertFalse(out.contains("com.benign.LowOne"), out);
        assertFalse(out.contains("com.benign.LowTwo"), out);
        assertTrue(out.contains(p.toString()) || out.contains("scan.json"), out);
        assertTrue(out.contains("19440"), out);
    }

    @Test
    void null_className_prints_placeholder_no_npe() throws Exception {
        String json = "{"
                + "\"target\":{\"pid\":1},"
                + "\"summary\":{\"critical\":0,\"high\":1,\"suspicious\":0,\"low\":0},"
                + "\"findings\":[{\"level\":\"high\",\"type\":\"tomcat-servlet\",\"className\":null,\"score\":8}]"
                + "}";
        Path p = writeReport(json);
        String out = capture(p.toString(), 1);
        assertTrue(out.contains("high") && out.contains("<null>"), out);
    }

    @Test
    void missing_file_prints_degraded_line_no_throw() throws Exception {
        String out = capture(tempDir.resolve("does-not-exist.json").toString(), 7);
        assertTrue(out.contains("summary unavailable"), out);
    }

    @Test
    void corrupt_json_prints_degraded_line_no_throw() throws Exception {
        Path p = writeReport("{ this is not valid json ");
        String out = capture(p.toString(), 7);
        assertTrue(out.contains("summary unavailable"), out);
    }

    private String scanLineFor(String findingsJson) throws Exception {
        String json = "{\"target\":{\"pid\":1},"
                + "\"summary\":{\"critical\":1,\"high\":0,\"suspicious\":0,\"low\":0},"
                + "\"findings\":[" + findingsJson + "]}";
        return capture(writeReport(json).toString(), 1);
    }

    @Test
    void filter_shows_urlPatterns_as_path() throws Exception {
        String out = scanLineFor("{\"level\":\"critical\",\"type\":\"tomcat-filter\",\"className\":\"com.x.F\",\"score\":16,"
                + "\"attributes\":{\"urlPatterns\":[\"/*\"]}}");
        assertTrue(out.contains("path=[/*]"), out);
    }

    @Test
    void servlet_shows_mappings_as_path() throws Exception {
        String out = scanLineFor("{\"level\":\"critical\",\"type\":\"tomcat-servlet\",\"className\":null,\"score\":8,"
                + "\"attributes\":{\"mappings\":[\"/dsad/dsad\"]}}");
        assertTrue(out.contains("path=[/dsad/dsad]"), out);
    }

    @Test
    void spring_mapping_shows_pattern_as_path() throws Exception {
        String out = scanLineFor("{\"level\":\"critical\",\"type\":\"spring-mapping\",\"className\":\"com.x.C\",\"score\":12,"
                + "\"attributes\":{\"pattern\":\"/admin\"}}");
        assertTrue(out.contains("path=") && out.contains("/admin"), out);
    }

    @Test
    void spring_interceptor_shows_include_and_exclude() throws Exception {
        String out = scanLineFor("{\"level\":\"critical\",\"type\":\"spring-interceptor\",\"className\":\"com.x.I\",\"score\":12,"
                + "\"attributes\":{\"includePatterns\":[\"/api/**\"],\"excludePatterns\":[\"/api/login\"]}}");
        assertTrue(out.contains("path=[/api/**]"), out);
        assertTrue(out.contains("exclude=[/api/login]"), out);
    }

    @Test
    void agent_tampered_injectedStrings_truncated_over_five() throws Exception {
        String out = scanLineFor("{\"level\":\"critical\",\"type\":\"agent-bytecode-tampered\",\"className\":\"javax.servlet.http.HttpServlet\",\"score\":15,"
                + "\"attributes\":{\"injectedStrings\":[\"a1\",\"b2\",\"c3\",\"d4\",\"e5\",\"f6\",\"g7\"]}}");
        assertTrue(out.contains("a1") && out.contains("e5"), out);
        assertTrue(out.contains("...(+2 more)"), out);
        assertFalse(out.contains("f6"), out);
        assertFalse(out.contains("g7"), out);
    }

    @Test
    void agent_tampered_injectedStrings_no_truncation_when_few() throws Exception {
        String out = scanLineFor("{\"level\":\"critical\",\"type\":\"agent-bytecode-tampered\",\"className\":\"X\",\"score\":15,"
                + "\"attributes\":{\"injectedStrings\":[\"p1\",\"p2\",\"p3\"]}}");
        assertTrue(out.contains("p1") && out.contains("p3"), out);
        assertFalse(out.contains("more"), out);
    }

    @Test
    void listener_shows_trigger() throws Exception {
        String out = scanLineFor("{\"level\":\"high\",\"type\":\"tomcat-listener-request\",\"className\":\"com.x.L\",\"score\":8,"
                + "\"attributes\":{\"listenerKind\":\"request\"}}");
        assertTrue(out.contains("trigger=request"), out);
        assertFalse(out.contains("path="), out);
    }

    @Test
    void valve_shows_pipeline() throws Exception {
        String out = scanLineFor("{\"level\":\"high\",\"type\":\"tomcat-valve\",\"className\":\"com.x.V\",\"score\":9,"
                + "\"attributes\":{\"pipelineIndex\":2}}");
        assertTrue(out.contains("pipeline=2"), out);
    }

    @Test
    void transformer_shows_class() throws Exception {
        String out = scanLineFor("{\"level\":\"high\",\"type\":\"agent-transformer\",\"className\":\"com.x.T\",\"score\":9,"
                + "\"attributes\":{\"transformerClass\":\"com.x.T\"}}");
        assertTrue(out.contains("class=com.x.T"), out);
    }

    @Test
    void dynamic_class_has_no_location_segment() throws Exception {
        String out = scanLineFor("{\"level\":\"high\",\"type\":\"agent-dynamic-class\",\"className\":\"com.x.D\",\"score\":8,\"attributes\":{}}");
        assertFalse(out.contains("path="), out);
        assertFalse(out.contains("trigger="), out);
        assertFalse(out.contains("pipeline="), out);
        assertFalse(out.contains("class="), out);
    }

    @Test
    void missing_attributes_field_no_throw_no_segment() throws Exception {
        String out = scanLineFor("{\"level\":\"critical\",\"type\":\"tomcat-filter\",\"className\":\"com.x.F\",\"score\":16}");
        assertTrue(out.contains("com.x.F"), out);
        assertFalse(out.contains("path="), out);
    }
}
