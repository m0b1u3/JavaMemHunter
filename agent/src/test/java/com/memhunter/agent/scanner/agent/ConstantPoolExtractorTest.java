package com.memhunter.agent.scanner.agent;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ConstantPoolExtractorTest {

    @Test
    void extracts_utf8_constants_from_real_class() throws Exception {
        byte[] bytes = readClassBytes("java/lang/String.class");
        Set<String> utf8 = ConstantPoolExtractor.utf8Constants(bytes);
        assertFalse(utf8.isEmpty(), "String.class must yield UTF8 constants");
        assertTrue(utf8.contains("toString"), "should contain method name toString");
        assertTrue(utf8.contains("hashCode"), "should contain method name hashCode");
    }

    @Test
    void handles_class_with_long_double_constants_without_slot_misalignment() throws Exception {
        byte[] bytes = readClassBytes("java/lang/Long.class");
        Set<String> utf8 = ConstantPoolExtractor.utf8Constants(bytes);
        assertTrue(utf8.contains("parseLong"),
                "Long.class parsed with correct slot counting must contain parseLong");
    }

    @Test
    void returns_empty_for_null_or_garbage_without_throwing() {
        assertTrue(ConstantPoolExtractor.utf8Constants(null).isEmpty());
        assertTrue(ConstantPoolExtractor.utf8Constants(new byte[]{1, 2, 3}).isEmpty());
        assertTrue(ConstantPoolExtractor.utf8Constants(new byte[0]).isEmpty());
    }

    private byte[] readClassBytes(String resourcePath) throws Exception {
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
