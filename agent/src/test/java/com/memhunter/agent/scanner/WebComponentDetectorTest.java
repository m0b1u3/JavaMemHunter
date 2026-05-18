package com.memhunter.agent.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class WebComponentDetectorTest {

    @Test
    void detects_nothing_for_plain_class() {
        assertNull(WebComponentDetector.classify(String.class));
    }

    @Test
    void detects_runnable_as_nothing() {
        assertNull(WebComponentDetector.classify(Runnable.class));
    }

    interface FakeFilter extends javax.servlet.Filter {}

    @Test
    void detects_javax_filter() {
        assertEquals("Filter", WebComponentDetector.classify(FakeFilter.class));
    }
}
