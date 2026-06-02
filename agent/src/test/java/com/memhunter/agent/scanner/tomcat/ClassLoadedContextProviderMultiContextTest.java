package com.memhunter.agent.scanner.tomcat;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression guard for the multi-webapp fix: findAllContexts must no longer stop after the
 * WebappClassLoader strategy. The precise StandardContext class-name match makes a full
 * positive unit test impractical (cannot fabricate a real StandardContext), so the authoritative
 * verification is the live multi-webapp Tomcat E2E. This test just pins down that the method
 * is exception-safe and returns empty when no Tomcat is present.
 */
class ClassLoadedContextProviderMultiContextTest {

    @Test
    void findAllContexts_returns_empty_without_tomcat_and_does_not_throw() {
        ClassLoadedContextProvider provider = new ClassLoadedContextProvider();
        java.lang.instrument.Instrumentation fakeInst =
            (java.lang.instrument.Instrumentation) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{java.lang.instrument.Instrumentation.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getAllLoadedClasses")) return new Class<?>[0];
                    if (method.getReturnType() == boolean.class) return false;
                    return null;
                });
        List<Object> result = provider.findAllContexts(fakeInst);
        assertNotNull(result);
        assertTrue(result.isEmpty(), "no Tomcat -> empty, no exception");
    }
}
