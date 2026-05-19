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
}
