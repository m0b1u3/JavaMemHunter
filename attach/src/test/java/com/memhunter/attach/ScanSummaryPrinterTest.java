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
}
