package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TomcatScanner {

    private final List<StandardContextProvider> providers;

    public TomcatScanner() {
        this.providers = Arrays.asList(
                new MBeanContextProvider(),
                new ClassLoadedContextProvider()
        );
    }

    /** Test seam */
    TomcatScanner(List<StandardContextProvider> providers) {
        this.providers = providers;
    }

    public List<Finding> scan(Instrumentation inst, ScanReport report) {
        List<Object> contexts = locateContexts(inst, report);
        return scanContexts(contexts, report);
    }

    /** Exposed for callers that already obtained contexts (e.g. agentmain reusing for Spring). */
    public List<Object> locateContexts(Instrumentation inst, ScanReport report) {
        for (StandardContextProvider provider : providers) {
            try {
                List<Object> ctxs = provider.findAllContexts(inst);
                if (ctxs != null && !ctxs.isEmpty()) return ctxs;
            } catch (Throwable t) {
                report.partialErrors.add(new ScanReport.PartialError(
                        provider.name(), "exception: " + t.getMessage()));
            }
        }
        report.partialErrors.add(new ScanReport.PartialError(
                "TomcatScanner", "no Tomcat StandardContext located"));
        return new ArrayList<>();
    }

    /** Scan the given contexts. Used by both scan() and by agentmain reusing located contexts. */
    public List<Finding> scanContexts(List<Object> contexts, ScanReport report) {
        if (contexts == null || contexts.isEmpty()) return new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        for (Object ctx : contexts) {
            findings.addAll(new TomcatFilterScanner(ctx).scan(report));
            findings.addAll(new TomcatServletScanner(ctx).scan(report));
            findings.addAll(new TomcatListenerScanner(ctx).scan(report));
            findings.addAll(new TomcatValveScanner(ctx).scan(report));
        }
        return findings;
    }
}
