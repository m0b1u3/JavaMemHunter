package com.memhunter.agent.scoring;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JvmGeneratedClassesTest {

    @Test
    void recognises_reflection_accessor_classes() {
        assertTrue(JvmGeneratedClasses.isJvmGenerated("sun.reflect.GeneratedMethodAccessor57"));
        assertTrue(JvmGeneratedClasses.isJvmGenerated("sun.reflect.GeneratedConstructorAccessor3"));
        assertTrue(JvmGeneratedClasses.isJvmGenerated("jdk.internal.reflect.GeneratedMethodAccessor1"));
    }

    @Test
    void recognises_lambda_and_proxy_classes() {
        assertTrue(JvmGeneratedClasses.isJvmGenerated("com.example.Foo$$Lambda$3/0x0000000800abc"));
        assertTrue(JvmGeneratedClasses.isJvmGenerated("com.sun.proxy.$Proxy58"));
        assertTrue(JvmGeneratedClasses.isJvmGenerated("$Proxy42"));
    }

    @Test
    void rejects_malicious_and_business_classes() {
        assertFalse(JvmGeneratedClasses.isJvmGenerated("com.evil.Shell"));
        assertFalse(JvmGeneratedClasses.isJvmGenerated("sun.hptabba.Xdozy"));
        assertFalse(JvmGeneratedClasses.isJvmGenerated("com.example.UserServlet"));
        assertFalse(JvmGeneratedClasses.isJvmGenerated(null));
    }
}
