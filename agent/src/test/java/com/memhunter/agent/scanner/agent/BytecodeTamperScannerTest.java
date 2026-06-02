package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class BytecodeTamperScannerTest {

    @Test
    void no_loaded_target_classes_means_no_findings() {
        // 真实 inst 无目标类加载 → findLoaded 返回 null → 跳过
        Object fakeInst = new Object() {
            public Class<?>[] getAllLoadedClasses() { return new Class<?>[0]; }
        };
        List<Finding> findings = new BytecodeTamperScanner().scan(fakeInst, new ScanReport());
        assertTrue(findings.isEmpty(), "无目标类加载 → 无 finding");
    }

    @Test
    void tamper_detected_when_captured_bytes_differ_from_jar() {
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return new byte[]{1, 2, 3}; }
            @Override byte[] readFromJar(Class<?> clazz) { return new byte[]{4, 5, 6}; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        List<Finding> findings = scanner.scan(new Object(), new ScanReport());
        assertFalse(findings.isEmpty(), "字节码不同必须产生 finding");
        Finding f = findings.get(0);
        assertEquals("agent-bytecode-tampered", f.type);
        assertEquals("critical", f.level);
        assertEquals(15, f.score);
        assertNotNull(f.attributes.get("tamperedClass"));
    }

    @Test
    void no_finding_when_bytes_identical() {
        byte[] same = new byte[]{1, 2, 3};
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return same; }
            @Override byte[] readFromJar(Class<?> clazz) { return same; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        assertTrue(scanner.scan(new Object(), new ScanReport()).isEmpty(), "字节码相同不应产生 finding");
    }

    @Test
    void skips_when_captureBytes_returns_null() {
        BytecodeTamperScanner scanner = new BytecodeTamperScanner() {
            @Override byte[] captureBytes(Object inst, Class<?> clazz) { return null; }
            @Override byte[] readFromJar(Class<?> clazz) { return new byte[]{1}; }
            @Override Class<?> findLoaded(Object inst, String name) { return String.class; }
        };
        assertTrue(scanner.scan(new Object(), new ScanReport()).isEmpty());
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
        assertFalse(report.partialErrors.isEmpty(), "异常必须记为 partialError");
    }
}
