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
    // getResourceAsStream 重载让 ClassBytecodeReader 能读到字节
    static class WeirdClassLoader extends ClassLoader {
        private final java.util.Map<String, byte[]> defined = new java.util.HashMap<>();
        WeirdClassLoader() { super(null); }
        Class<?> define(String name, byte[] b) {
            defined.put(name.replace('.', '/') + ".class", b);
            return defineClass(name, b, 0, b.length);
        }
        @Override
        public java.io.InputStream getResourceAsStream(String resourcePath) {
            byte[] b = defined.get(resourcePath);
            if (b != null) return new java.io.ByteArrayInputStream(b);
            return super.getResourceAsStream(resourcePath);
        }
    }

    @Test
    void dynamic_class_without_malicious_bytecode_is_not_reported() throws Exception {
        WeirdClassLoader wcl = new WeirdClassLoader();
        byte[] classBytes = makeEmptyClass();
        Class<?> cleanDynamic = wcl.define("Payload", classBytes);
        FakeInst inst = new FakeInst(cleanDynamic);
        List<Finding> findings = new DynamicClassScanner().scan(inst, new ScanReport());
        assertTrue(findings.isEmpty(),
                "clean dynamic class (no Runtime.exec/defineClass) must not be reported in v0.12");
    }

    @Test
    void dynamic_class_with_malicious_bytecode_is_suspicious() throws Exception {
        WeirdClassLoader wcl = new WeirdClassLoader();
        byte[] classBytes = makeClassThatCallsDefineClass();
        Class<?> evilDynamic = wcl.define("Evil", classBytes);
        FakeInst inst = new FakeInst(evilDynamic);
        List<Finding> findings = new DynamicClassScanner().scan(inst, new ScanReport());
        assertFalse(findings.isEmpty(), "dynamic class calling defineClass must be reported");
        assertEquals("agent-dynamic-class", findings.get(0).type);
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

    /**
     * Loader that can define a class (so we get a real Class object with no codeSource),
     * but returns null from getResourceAsStream — making ClassBytecodeReader unable to read
     * the bytecode.
     */
    static class SilentLoader extends ClassLoader {
        SilentLoader() { super(null); }
        Class<?> define(String name, byte[] b) {
            return defineClass(name, b, 0, b.length);
        }
        @Override
        public java.io.InputStream getResourceAsStream(String resourcePath) {
            return null;  // intentionally unreadable
        }
    }

    /**
     * v0.12 known trade-off: when bytecode is unreadable we prefer to skip rather than
     * report (reduces false positives at the cost of potentially missing a shell class).
     * The observable-signal requirement mandates that a partialError warning is emitted
     * so operators can manually review.
     */
    @Test
    void dynamic_class_with_unreadable_bytecode_not_reported_but_emits_partial_error() throws Exception {
        SilentLoader sl = new SilentLoader();
        // Build a minimal class named "Ghost" via ASM so the bytecode name matches
        Class<?> silentDynamic = sl.define("Ghost", makeMinimalClass("Ghost"));
        FakeInst inst = new FakeInst(silentDynamic);
        ScanReport report = new ScanReport();
        List<Finding> findings = new DynamicClassScanner().scan(inst, report);

        // v0.12 trade-off: bytecode unreadable → not escalated to a finding (prefer under-report)
        assertTrue(findings.isEmpty(),
                "dynamic class with unreadable bytecode must NOT be reported (v0.12 false-positive reduction)");

        // Observable signal: partialErrors must contain a warning for manual review
        assertFalse(report.partialErrors.isEmpty(),
                "a partialError warning must be emitted when bytecode is unreadable");
        assertTrue(report.partialErrors.stream()
                .anyMatch(e -> e.scanner.equals("DynamicClassScanner") && e.reason.contains("Ghost")),
                "partialError must mention the class name 'Ghost'");
    }

    @Test
    void class_with_valid_codeSource_is_not_reported() {
        // org.junit.jupiter.api.Test 这个类来自 junit jar，有真实 codeSource，
        // 由标准 classLoader 加载 → 不应被标记为可疑
        FakeInst inst = new FakeInst(org.junit.jupiter.api.Test.class);
        List<Finding> findings = new DynamicClassScanner().scan(inst, new ScanReport());
        assertTrue(findings.isEmpty(), "有 codeSource 的标准类不应上报");
    }

    /** Build a minimal empty class with the given internal name using ASM. */
    private static byte[] makeMinimalClass(String simpleName) {
        org.objectweb.asm.ClassWriter cw =
            new org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES | org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
        cw.visit(org.objectweb.asm.Opcodes.V1_8, org.objectweb.asm.Opcodes.ACC_PUBLIC,
                simpleName, null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor ctor =
            cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(org.objectweb.asm.Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
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

    private byte[] makeClassThatCallsDefineClass() {
        org.objectweb.asm.ClassWriter cw =
            new org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES | org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
        cw.visit(org.objectweb.asm.Opcodes.V1_8, org.objectweb.asm.Opcodes.ACC_PUBLIC,
                "Evil", null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor ctor =
            cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(org.objectweb.asm.Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();
        org.objectweb.asm.MethodVisitor m =
            cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC, "load",
                    "(Ljava/lang/ClassLoader;[B)Ljava/lang/Class;", null, null);
        m.visitCode();
        m.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 1);
        m.visitInsn(org.objectweb.asm.Opcodes.ACONST_NULL);
        m.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 2);
        m.visitInsn(org.objectweb.asm.Opcodes.ICONST_0);
        m.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 2);
        m.visitInsn(org.objectweb.asm.Opcodes.ARRAYLENGTH);
        m.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader",
                "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;", false);
        m.visitInsn(org.objectweb.asm.Opcodes.ARETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }
}
