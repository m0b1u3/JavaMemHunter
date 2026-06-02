package com.memhunter.agent.util;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ReflectUtilTest {

    static class Base {
        private String inheritedField = "base-value";
    }

    static class Sample extends Base {
        public String publicField = "p";
        private String privateField = "priv";
        public String hello() { return "world"; }
    }

    @Test
    void tryReadField_reads_public_field() {
        Sample s = new Sample();
        assertEquals(Optional.of("p"), ReflectUtil.tryReadField(s, "publicField"));
    }

    @Test
    void tryReadField_reads_private_field() {
        Sample s = new Sample();
        assertEquals(Optional.of("priv"), ReflectUtil.tryReadField(s, "privateField"));
    }

    @Test
    void tryReadField_walks_superclass_chain() {
        Sample s = new Sample();
        assertEquals(Optional.of("base-value"), ReflectUtil.tryReadField(s, "inheritedField"));
    }

    @Test
    void tryReadField_returns_empty_on_missing() {
        Sample s = new Sample();
        assertFalse(ReflectUtil.tryReadField(s, "noSuchField").isPresent());
    }

    @Test
    void tryReadField_returns_empty_on_null_target() {
        assertFalse(ReflectUtil.tryReadField(null, "anything").isPresent());
    }

    @Test
    void tryReadAnyOf_returns_first_matching() {
        Sample s = new Sample();
        assertEquals(Optional.of("p"),
                ReflectUtil.tryReadAnyOf(s, "missing1", "publicField", "missing2"));
    }

    @Test
    void tryReadAnyOf_returns_empty_when_none_match() {
        Sample s = new Sample();
        assertFalse(ReflectUtil.tryReadAnyOf(s, "a", "b", "c").isPresent());
    }

    @Test
    void tryInvoke_calls_no_arg_method() {
        Sample s = new Sample();
        assertEquals(Optional.of("world"), ReflectUtil.tryInvoke(s, "hello"));
    }

    @Test
    void tryInvoke_returns_empty_on_missing_method() {
        Sample s = new Sample();
        assertFalse(ReflectUtil.tryInvoke(s, "nonexistent").isPresent());
    }

    @Test
    void tryInvokeWithArg_calls_method_with_matching_arg_type() {
        Object target = new Object() {
            @SuppressWarnings("unused")
            public String greet(String name) { return "hello-" + name; }
        };
        Optional<Object> result = ReflectUtil.tryInvokeWithArg(target, "greet", "world");
        assertTrue(result.isPresent());
        assertEquals("hello-world", result.get());
    }

    @Test
    void tryInvokeWithArg_returns_empty_when_method_not_found() {
        Optional<Object> result = ReflectUtil.tryInvokeWithArg("anyString", "noSuchMethod", 42);
        assertFalse(result.isPresent());
    }

    @Test
    void tryInvokeWithArg_returns_empty_when_target_is_null() {
        Optional<Object> result = ReflectUtil.tryInvokeWithArg(null, "anything", "arg");
        assertFalse(result.isPresent());
    }

    @Test
    void tryInvokeWithArg_returns_empty_when_method_throws() {
        Object target = new Object() {
            @SuppressWarnings("unused")
            public void boom(String s) { throw new RuntimeException("bang"); }
        };
        Optional<Object> result = ReflectUtil.tryInvokeWithArg(target, "boom", "x");
        assertFalse(result.isPresent());
    }
}
