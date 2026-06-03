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
    void target_classes_cover_behinder_redefine_targets() throws Exception {
        java.lang.reflect.Field f = BytecodeTamperScanner.class.getDeclaredField("TARGET_CLASSES");
        f.setAccessible(true);
        String[] targets = (String[]) f.get(null);
        java.util.List<String> list = java.util.Arrays.asList(targets);
        // Behinder probes/redefines these servlet base classes (service()/execute()).
        assertTrue(list.contains("javax.servlet.http.HttpServlet"),
                "must monitor javax HttpServlet");
        assertTrue(list.contains("jakarta.servlet.http.HttpServlet"),
                "must monitor jakarta HttpServlet (Spring Boot 3 / Tomcat 10)");
        assertTrue(list.contains("weblogic.servlet.internal.ServletStubImpl"),
                "must monitor WebLogic ServletStubImpl (explicit Behinder target)");
    }

    @Test
    void no_loaded_target_classes_means_no_findings() {
        Object fakeInst = new Object() {
            public Class<?>[] getAllLoadedClasses() { return new Class<?>[0]; }
        };
        List<Finding> findings = new BytecodeTamperScanner().scan(fakeInst, new ScanReport(), null);
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
        assertTrue(scanner.scan(new Object(), new ScanReport(), null).isEmpty(),
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
        List<Finding> fs = scanner.scan(new Object(), new ScanReport(), null);
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
        assertTrue(scanner.scan(new Object(), new ScanReport(), null).isEmpty(),
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
        List<Finding> findings = scanner.scan(new Object(), report, null);
        assertTrue(findings.isEmpty());
        assertFalse(report.partialErrors.isEmpty(), "exception must be recorded as partialError");
    }

    @Test
    void injected_string_constants_are_extracted_into_finding() throws Exception {
        final byte[] original = readClassBytesStatic("java/lang/String.class");
        final byte[] modified = readClassBytesStatic("java/lang/Integer.class");
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return modified; }
            @Override byte[] readFromJar(Class<?> clazz) { return original; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        java.util.List<Finding> fs = scanner.scan(new Object(), new ScanReport(), null);
        assertFalse(fs.isEmpty());
        Object raw = fs.get(0).attributes.get("injectedStringsRaw");
        assertNotNull(raw, "injectedStringsRaw must be present");
        assertTrue(raw instanceof java.util.List && !((java.util.List<?>) raw).isEmpty(),
                "injectedStringsRaw must be a non-empty list");
    }

    @Test
    void filterSuspicious_keeps_paths_and_drops_descriptors() {
        BytecodeTamperScanner scanner = new BytecodeTamperScanner();
        java.util.Set<String> input = new java.util.LinkedHashSet<>(java.util.Arrays.asList(
                "/yyy",
                "()V",
                "Ljava/lang/String;",
                "get",
                "doFilterInternal",
                "aGVsbG93b3JsZA=="
        ));
        java.util.List<String> kept = scanner.filterSuspicious(input);
        assertTrue(kept.contains("/yyy"), "path must be kept");
        assertTrue(kept.contains("doFilterInternal"), "long token must be kept");
        assertTrue(kept.contains("aGVsbG93b3JsZA=="), "high-entropy string must be kept");
        assertFalse(kept.contains("()V"), "method descriptor must be dropped");
        assertFalse(kept.contains("Ljava/lang/String;"), "type descriptor must be dropped");
        assertFalse(kept.contains("get"), "short token must be dropped");
    }

    @Test
    void evidence_dumped_false_when_no_evidence_dir() throws Exception {
        final byte[] original = readClassBytesStatic("java/lang/String.class");
        final byte[] modified = readClassBytesStatic("java/lang/Integer.class");
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return modified; }
            @Override byte[] readFromJar(Class<?> clazz) { return original; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        java.util.List<Finding> fs = scanner.scan(new Object(), new ScanReport(), null);
        assertFalse(fs.isEmpty());
        assertEquals(Boolean.FALSE, fs.get(0).attributes.get("evidenceDumped"));
        assertNotNull(fs.get(0).attributes.get("injectedStrings"));
    }

    @Test
    void evidence_class_files_written_when_evidence_dir_given(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp) throws Exception {
        final byte[] original = readClassBytesStatic("java/lang/String.class");
        final byte[] modified = readClassBytesStatic("java/lang/Integer.class");
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return modified; }
            @Override byte[] readFromJar(Class<?> clazz) { return original; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        java.util.List<Finding> fs = scanner.scan(new Object(), new ScanReport(), tmp.toString());
        assertFalse(fs.isEmpty());
        Finding f = fs.get(0);
        assertEquals(Boolean.TRUE, f.attributes.get("evidenceDumped"));
        java.nio.file.Path dir = tmp.resolve("evidence").resolve(f.id);
        assertTrue(java.nio.file.Files.exists(dir.resolve("tampered.class")), "tampered.class must exist");
        assertTrue(java.nio.file.Files.exists(dir.resolve("original.class")), "original.class must exist");
        assertArrayEquals(modified, java.nio.file.Files.readAllBytes(dir.resolve("tampered.class")));
        assertArrayEquals(original, java.nio.file.Files.readAllBytes(dir.resolve("original.class")));
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
