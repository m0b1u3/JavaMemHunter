package com.memhunter.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.spring.SpringInterceptorScanner;
import com.memhunter.agent.scanner.spring.SpringMappingScanner;
import com.memhunter.agent.scanner.tomcat.TomcatFilterScanner;
import com.memhunter.agent.scanner.tomcat.TomcatListenerScanner;
import com.memhunter.agent.scanner.tomcat.TomcatServletScanner;
import com.memhunter.agent.scanner.tomcat.TomcatValveScanner;
import com.memhunter.agent.scoring.RuleEngine;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.function.Function;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Cross-scanner finding lookup. Runs all 4 Tomcat scanners (when tomcatCtx is
 * non-null) plus the 2 Spring scanners (when springCtx is non-null), scores
 * the merged result via RuleEngine, then matches by id.
 *
 * <p>Used by both clean dispatch and verify so that both code paths see the
 * same finding universe (the v0.8.1 root cause of false-negative verify was a
 * Filter-only scan in VerifyExecutor that disagreed with the clean path).
 */
public final class FindingLocator {

    private FindingLocator() {}

    /** Result of a cross-context lookup: the finding plus the contexts it was found in. */
    public static final class Located {
        public final Finding finding;
        public final Object tomcatCtx;
        public final Object springCtx;
        public Located(Finding finding, Object tomcatCtx, Object springCtx) {
            this.finding = finding;
            this.tomcatCtx = tomcatCtx;
            this.springCtx = springCtx;
        }
    }

    /**
     * Locate a finding by id across ALL Tomcat contexts. For each context, the caller-supplied
     * resolver computes the matching Spring application context; the existing single-context
     * {@link #find} is then run. The first context whose scan yields a matching id wins.
     *
     * <p>This is the multi-webapp fix (v1.2): clean/verify previously only looked in the first
     * context, so a memshell registered in any other webapp (e.g. ROOT when docs deploys first)
     * was reported "finding not located". scan never had this bug because it iterates all contexts.
     *
     * @return the matching {@link Located}, or {@code null} if no context contains the id.
     */
    public static Located findAcrossContexts(java.util.List<?> tomcatContexts,
                                             Function<Object, Object> springCtxResolver,
                                             String id) {
        if (tomcatContexts == null || id == null) return null;
        for (Object tctx : tomcatContexts) {
            if (tctx == null) continue;
            Object sctx = springCtxResolver == null ? null : springCtxResolver.apply(tctx);
            Finding f = find(tctx, sctx, id);
            if (f != null) return new Located(f, tctx, sctx);
        }
        return null;
    }

    public static Finding find(Object tomcatCtx, Object springCtx, String id) {
        if (id == null) return null;
        ScanReport report = new ScanReport();
        List<Finding> all = new ArrayList<>();
        if (tomcatCtx != null) {
            all.addAll(new TomcatFilterScanner(tomcatCtx).scan(report));
            all.addAll(new TomcatServletScanner(tomcatCtx).scan(report));
            all.addAll(new TomcatListenerScanner(tomcatCtx).scan(report));
            all.addAll(new TomcatValveScanner(tomcatCtx).scan(report));
        }
        if (springCtx != null) {
            all.addAll(new SpringMappingScanner(springCtx).scan(report));
            List<Finding> interceptorFindings = new SpringInterceptorScanner(springCtx).scan(report);
            if (interceptorFindings.isEmpty() && !isSpringWebMvcPresent(springCtx)) {
                // Fallback: AbstractHandlerMapping not loadable (e.g. tests without spring-webmvc).
                // Walk beans directly, same id scheme as the scanner.
                interceptorFindings = springInterceptorFallbackScan(springCtx);
            }
            all.addAll(interceptorFindings);
        }
        // v0.12.1: let bytecode rules read webapp classes via the tomcat webapp loader.
        List<ClassLoader> webappLoaders = new ArrayList<>();
        if (tomcatCtx != null) {
            ClassLoader wl = com.memhunter.agent.scanner.tomcat.WebappCodeSourceResolver
                    .webappClassLoader(tomcatCtx);
            if (wl != null) webappLoaders.add(wl);
        }
        new RuleEngine().evaluate(all,
                new ScanContext(springCtx, Whitelist.defaults(), false, BaselineIndex.empty(),
                        webappLoaders));
        for (Finding f : all) {
            if (f != null && id.equals(f.id)) return f;
        }
        return null;
    }

    private static boolean isSpringWebMvcPresent(Object springCtx) {
        try {
            Class.forName(
                    "org.springframework.web.servlet.handler.AbstractHandlerMapping",
                    false,
                    springCtx.getClass().getClassLoader());
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Finding> springInterceptorFallbackScan(Object springCtx) {
        List<Finding> result = new ArrayList<>();
        Set<String> seenIds = new HashSet<>();
        try {
            Method m = springCtx.getClass().getMethod("getBeansOfType", Class.class);
            Map<String, Object> beans = (Map<String, Object>) m.invoke(springCtx, Object.class);
            if (beans == null) return result;
            for (Object mappingBean : beans.values()) {
                Object adapted = ReflectUtil.tryReadField(mappingBean, "adaptedInterceptors").orElse(null);
                if (!(adapted instanceof Collection)) continue;
                for (Object interceptor : (Collection<Object>) adapted) {
                    if (interceptor == null) continue;
                    Class<?> clazz = interceptor.getClass();
                    String fid = FindingIdGenerator.generate("spring-interceptor", clazz.getName(), "");
                    if (!seenIds.add(fid)) continue;
                    Finding f = new Finding();
                    f.type = "spring-interceptor";
                    f.name = clazz.getSimpleName();
                    f.className = clazz.getName();
                    f.id = fid;
                    result.add(f);
                }
            }
        } catch (Throwable ignored) {}
        return result;
    }
}
