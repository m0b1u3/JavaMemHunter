package com.memhunter.testinjector;

import jakarta.servlet.ServletContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * WARNING: This class is for end-to-end testing only.
 *
 * It exposes endpoints under /inject/* that register Filter/Servlet/Spring components
 * dynamically AT RUNTIME, simulating the behavior of a Java mem-shell injection.
 *
 * Do NOT include this class in any production build.
 */
@RestController
public class ShellSimulator {

    private final ServletContext servletContext;
    private final ConfigurableApplicationContext appContext;

    @Autowired
    public ShellSimulator(ServletContext servletContext, ConfigurableApplicationContext appContext) {
        this.servletContext = servletContext;
        this.appContext = appContext;
    }

    @GetMapping("/inject/filter")
    public String injectFilter() {
        new FakeFilterInjector(servletContext).inject();
        return "filter injected: FakeFilter";
    }

    @GetMapping("/inject/servlet")
    public String injectServlet() {
        new FakeServletInjector(servletContext).inject();
        return "servlet injected: FakeServlet";
    }

    @GetMapping("/inject/spring-mapping")
    public String injectSpringMapping() {
        new FakeSpringControllerInjector(appContext).inject();
        return "spring mapping injected: /spring-fake";
    }

    @GetMapping("/inject/spring-interceptor")
    public String injectSpringInterceptor() {
        new FakeSpringInterceptorInjector(appContext).inject();
        return "spring interceptor injected: FakeInterceptor";
    }

    @GetMapping("/inject/listener")
    public String injectListener() {
        new FakeListenerInjector(servletContext).inject();
        return "listener injected: FakeListener";
    }

    @GetMapping("/inject/valve")
    public String injectValve() {
        new FakeValveInjector(servletContext).inject();
        return "valve injected: FakeValve";
    }
}
