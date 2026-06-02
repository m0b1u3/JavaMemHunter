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
                int count = ctxs == null ? 0 : ctxs.size();
                report.partialErrors.add(new ScanReport.PartialError(
                        provider.name(), "located " + count + " context(s)"));
                if (ctxs != null && !ctxs.isEmpty()) return ctxs;
            } catch (Throwable t) {
                report.partialErrors.add(new ScanReport.PartialError(
                        provider.name(), "exception: " + t.getClass().getSimpleName() + ": " + t.getMessage()));
            }
        }
        report.partialErrors.add(new ScanReport.PartialError(
                "TomcatScanner", "no Tomcat StandardContext located; "
                        + collectDiagnostics(inst)));
        return new ArrayList<>();
    }

    /** Diagnostic snapshot of loaded classes + threads to help debug provider failure on a given JVM. */
    private String collectDiagnostics(Instrumentation inst) {
        StringBuilder sb = new StringBuilder();
        boolean hasEngineClass = false;
        boolean hasContextClass = false;
        int webappLoaders = 0;
        java.util.Set<String> webappLoaderNames = new java.util.LinkedHashSet<>();
        for (Class<?> c : inst.getAllLoadedClasses()) {
            String n = c.getName();
            if ("org.apache.catalina.core.StandardEngine".equals(n)) hasEngineClass = true;
            if ("org.apache.catalina.core.StandardContext".equals(n)) hasContextClass = true;
            ClassLoader cl = c.getClassLoader();
            if (cl != null) {
                String cln = cl.getClass().getName();
                if (cln.endsWith("WebappClassLoaderBase")
                        || cln.endsWith("ParallelWebappClassLoader")
                        || cln.endsWith("WebappClassLoader")
                        || cln.contains("TomcatEmbedded")) {
                    if (webappLoaderNames.add(cln)) webappLoaders++;
                }
            }
        }
        sb.append("StandardEngine.class=").append(hasEngineClass);
        sb.append(", StandardContext.class=").append(hasContextClass);
        sb.append(", webappClassLoaderTypes=").append(webappLoaderNames);
        // Thread names (Tomcat-ish only)
        java.util.List<String> tomcatThreads = new java.util.ArrayList<>();
        ThreadGroup root = Thread.currentThread().getThreadGroup();
        while (root.getParent() != null) root = root.getParent();
        Thread[] threads = new Thread[root.activeCount() + 32];
        int n = root.enumerate(threads, true);
        for (int i = 0; i < n; i++) {
            Thread t = threads[i];
            if (t == null) continue;
            String tn = t.getName();
            if (tn != null && (tn.contains("http-") || tn.contains("Acceptor") || tn.contains("acceptor")
                    || tn.contains("Poller") || tn.contains("poller") || tn.contains("tomcat"))) {
                tomcatThreads.add(tn);
            }
        }
        sb.append(", tomcatThreads=").append(tomcatThreads);
        return sb.toString();
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
