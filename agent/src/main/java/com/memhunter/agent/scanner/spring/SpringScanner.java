package com.memhunter.agent.scanner.spring;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SpringScanner {

    private final List<ApplicationContextProvider> providers;

    public SpringScanner() {
        this.providers = Arrays.asList(
                new DispatcherServletProvider(),
                new ServletContextAttrProvider()
        );
    }

    SpringScanner(List<ApplicationContextProvider> providers) {
        this.providers = providers;
    }

    public List<Finding> scan(List<Object> tomcatContexts, List<Object> tomcatServletInstances,
                              ScanReport report) {
        List<Object> appCtxs = locateContexts(tomcatContexts, tomcatServletInstances, report);
        if (appCtxs.isEmpty()) return new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        for (Object appCtx : appCtxs) {
            findings.addAll(new SpringMappingScanner(appCtx).scan(report));
            findings.addAll(new SpringInterceptorScanner(appCtx).scan(report));
        }
        return findings;
    }

    public List<Object> locateContexts(List<Object> tomcatContexts, List<Object> tomcatServletInstances,
                                ScanReport report) {
        for (ApplicationContextProvider p : providers) {
            try {
                List<Object> r = p.findAll(tomcatContexts, tomcatServletInstances);
                if (r != null && !r.isEmpty()) return r;
            } catch (Throwable t) {
                report.partialErrors.add(new ScanReport.PartialError(
                        p.name(), "exception: " + t.getMessage()));
            }
        }
        report.partialErrors.add(new ScanReport.PartialError(
                "SpringScanner", "no Spring ApplicationContext located"));
        return new ArrayList<>();
    }
}
