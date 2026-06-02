package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class DynamicClassScannerTest {

    // 假 Instrumentation：返回固定类集合
    static class FakeInst {
        private final Class<?>[] classes;
        FakeInst(Class<?>... classes) { this.classes = classes; }
        public Class<?>[] getAllLoadedClasses() { return classes; }
    }

    // 非标准 ClassLoader（不在 STANDARD_LOADERS 里），super(null) 使 codeSource 为空
    static class WeirdClassLoader extends ClassLoader {
        WeirdClassLoader() { super(null); }
        Class<?> define(String name, byte[] b) { return defineClass(name, b, 0, b.length); }
    }

    @Test
    void class_with_null_codeSource_and_unusual_classLoader_is_suspicious() {
        WeirdClassLoader wcl = new WeirdClassLoader();
        byte[] classBytes = makeEmptyClass();
        Class<?> dynamicClass = wcl.define("Payload", classBytes);

        FakeInst inst = new FakeInst(dynamicClass);
        List<Finding> findings = new DynamicClassScanner().scan(inst, new ScanReport());
        assertFalse(findings.isEmpty(), "weird loader + no codeSource 应可疑");
        assertEquals("agent-dynamic-class", findings.get(0).type);
        assertTrue(findings.get(0).score >= 4);
    }

    @Test
    void bootstrap_class_is_not_reported() {
        FakeInst inst = new FakeInst(String.class);  // bootstrap loader → classLoader 为 null
        List<Finding> findings = new DynamicClassScanner().scan(inst, new ScanReport());
        assertTrue(findings.isEmpty(), "bootstrap 类不应上报");
    }

    @Test
    void exception_in_getAllLoadedClasses_records_partial_error() {
        Object badInst = new Object();  // 没有 getAllLoadedClasses 方法
        ScanReport report = new ScanReport();
        List<Finding> findings = new DynamicClassScanner().scan(badInst, report);
        assertTrue(findings.isEmpty());
        assertFalse(report.partialErrors.isEmpty());
    }

    // 最小合法 class 字节码：public class Payload {}（class 文件版本 49 = Java 5）
    private static byte[] makeEmptyClass() {
        return new byte[]{
            (byte)0xCA,(byte)0xFE,(byte)0xBA,(byte)0xBE,
            0,0,0,49,
            0,10,
            7,0,2,
            1,0,7,'P','a','y','l','o','a','d',
            7,0,4,
            1,0,16,'j','a','v','a','/','l','a','n','g','/','O','b','j','e','c','t',
            1,0,6,'<','i','n','i','t','>',
            1,0,3,'(',')','V',
            1,0,4,'C','o','d','e',
            12,0,5,0,6,
            10,0,3,0,8,
            0x00,0x21,
            0,1,0,3,
            0,0,0,0,
            0,1,
            0x00,0x01,
            0,5,0,6,0,1,
            0,7,
            0,0,0,17,
            0,1,0,1,
            0,0,0,5,
            42,(byte)183,0,9,
            (byte)177,
            0,0,0,0,
            0,0
        };
    }
}
