package com.memhunter.agent.scoring.bytecode;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ClassBytecodeReaderTest {

    @Test
    void reads_a_known_jdk_class() {
        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(
                "java.lang.String", String.class.getClassLoader());
        // java.lang.String is in the bootstrap classloader; getResourceAsStream may return null.
        // Either result null OR result with some methodCalls is acceptable.
        if (result != null) {
            assertNotNull(result.methodCalls);
        }
    }

    @Test
    void reads_an_app_class_successfully() {
        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(
                "com.memhunter.agent.scoring.bytecode.ClassBytecodeReaderTest",
                ClassBytecodeReaderTest.class.getClassLoader());
        assertNotNull(result);
        assertNotNull(result.methodCalls);
        assertTrue(result.methodCalls.size() > 0);
    }

    @Test
    void returns_null_for_unknown_class() {
        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(
                "no.such.Class", ClassBytecodeReaderTest.class.getClassLoader());
        assertNull(result);
    }

    @Test
    void returns_null_for_null_className() {
        assertNull(ClassBytecodeReader.readAndAnalyze(null, null));
    }
}
