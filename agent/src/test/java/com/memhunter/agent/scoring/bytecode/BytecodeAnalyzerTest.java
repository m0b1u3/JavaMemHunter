package com.memhunter.agent.scoring.bytecode;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BytecodeAnalyzerTest {

    /**
     * Helper class that calls known methods. Used by tests to verify ASM picks them up.
     */
    static class SampleWithKnownCalls {
        void doStuff() throws Exception {
            // String concatenation compiles to StringBuilder#append calls
            String s = "hello" + System.currentTimeMillis();
            // Direct HashMap#put call
            java.util.HashMap<String, String> m = new java.util.HashMap<>();
            m.put("a", "b");
        }
    }

    @Test
    void analyzes_a_class_and_finds_its_method_calls() {
        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(
                SampleWithKnownCalls.class.getName(), getClass().getClassLoader());
        assertNotNull(result);
        assertTrue(result.hasMethodCall("java/util/HashMap", "put"),
                "expected HashMap#put in: " + result.methodCalls);
    }

    @Test
    void empty_class_yields_empty_or_minimal_set() {
        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(
                "java.lang.Object", Object.class.getClassLoader());
        if (result != null) {
            assertNotNull(result.methodCalls);
        }
    }

    /**
     * Helper containing a lambda that references Runtime.exec. On JDK 9+ this compiles
     * to invokedynamic + LambdaMetafactory whose bootstrap args include a Handle to the
     * synthetic method holding the lambda body. The body itself calls Runtime.exec via
     * invokevirtual, but we also want to capture the Handle reference path for robustness.
     */
    static class SampleWithLambda {
        Runnable r = () -> {
            try {
                Runtime.getRuntime().exec("nope");
            } catch (Exception ignored) {}
        };
    }

    @Test
    void analyzes_lambda_runtime_exec_call() {
        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(
                SampleWithLambda.class.getName(), getClass().getClassLoader());
        assertNotNull(result);
        assertTrue(result.hasMethodCall("java/lang/Runtime", "exec"),
                "expected Runtime#exec found via lambda in: " + result.methodCalls);
    }
}
