package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BytecodeTamperScannerTest {

    @Test
    void no_loaded_target_classes_means_no_findings() {
        Object fakeInst = new Object() {
            public Class<?>[] getAllLoadedClasses() { return new Class<?>[0]; }
        };
        List<Finding> findings = new BytecodeTamperScanner().scan(fakeInst, new ScanReport());
        assertTrue(findings.isEmpty(), "no loaded target classes -> no findings");
    }

    @Test
    void identical_bytecode_produces_no_finding() throws Exception {
        final byte[] realBytes = readClassBytes("java/lang/String.class");
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return realBytes; }
            @Override byte[] readFromJar(Class<?> clazz) { return realBytes; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        assertTrue(scanner.scan(new Object(), new ScanReport()).isEmpty(),
                "identical method fingerprints must not be reported");
    }

    @Test
    void different_method_set_produces_tamper_finding() throws Exception {
        final byte[] stringBytes = readClassBytes("java/lang/String.class");
        final byte[] integerBytes = readClassBytes("java/lang/Integer.class");
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return stringBytes; }
            @Override byte[] readFromJar(Class<?> clazz) { return integerBytes; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        List<Finding> fs = scanner.scan(new Object(), new ScanReport());
        assertFalse(fs.isEmpty(), "differing method fingerprints must produce a finding");
        Finding f = fs.get(0);
        assertEquals("agent-bytecode-tampered", f.type);
        assertEquals("critical", f.level);
        assertEquals(15, f.score);
        assertNotNull(f.attributes.get("tamperedMethods"));
    }

    @Test
    void skips_when_captureBytes_returns_null() {
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return null; }
            @Override byte[] readFromJar(Class<?> clazz) throws Exception { return readClassBytesStatic("java/lang/String.class"); }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        assertTrue(scanner.scan(new Object(), new ScanReport()).isEmpty(),
                "null captured bytes must be skipped before fingerprinting");
    }

    @Test
    void records_partial_error_when_captureBytes_throws() {
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) throws Exception {
                throw new RuntimeException("retransform failed");
            }
            @Override byte[] readFromJar(Class<?> clazz) { return new byte[]{1}; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        ScanReport report = new ScanReport();
        List<Finding> findings = scanner.scan(new Object(), report);
        assertTrue(findings.isEmpty());
        assertFalse(report.partialErrors.isEmpty(), "exception must be recorded as partialError");
    }

    private byte[] readClassBytes(String resourcePath) throws Exception {
        return readClassBytesStatic(resourcePath);
    }

    static byte[] readClassBytesStatic(String resourcePath) throws Exception {
        try (InputStream is = ClassLoader.getSystemResourceAsStream(resourcePath)) {
            assertNotNull(is, "test resource not found: " + resourcePath);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
            return buf.toByteArray();
        }
    }
}
