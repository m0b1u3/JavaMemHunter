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

    interface FakeRequestListener extends javax.servlet.ServletRequestListener {}
    interface FakeContextListener extends javax.servlet.ServletContextListener {}
    interface FakeSessionListener extends javax.servlet.http.HttpSessionListener {}

    @Test
    void detects_request_listener() {
        assertEquals("ListenerRequest", WebComponentDetector.classify(FakeRequestListener.class));
    }

    @Test
    void detects_context_listener() {
        assertEquals("ListenerContext", WebComponentDetector.classify(FakeContextListener.class));
    }

    @Test
    void detects_session_listener() {
        assertEquals("ListenerSession", WebComponentDetector.classify(FakeSessionListener.class));
    }
}
