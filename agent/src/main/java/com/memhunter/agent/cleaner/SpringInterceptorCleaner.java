package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.spring.SpringInterceptorScanner;
import com.memhunter.agent.util.ReflectUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SpringInterceptorCleaner extends AbstractSpringCleaner {

    private static final String HANDLER_MAPPING_CLASS =
            "org.springframework.web.servlet.handler.AbstractHandlerMapping";

    private InterceptorBackup currentBackup;
    Runnable hookAfterPhaseC = () -> {};

    public SpringInterceptorCleaner(Object applicationContext) {
        super(applicationContext);
    }

    @Override
    protected boolean supportsType(String type) {
        return "spring-interceptor".equals(type);
    }

    @Override
    protected Finding locateOnRescan(String findingId) {
        // Preferred path: delegate to the canonical scanner (real Spring runtime).
        List<Finding> findings = new SpringInterceptorScanner(applicationContext).scan(new ScanReport());
        for (Finding f : findings) {
            if (f.id != null && f.id.equals(findingId)) return f;
        }
        // Fallback: when AbstractHandlerMapping is not loadable (no spring-webmvc
        // on the context classloader, e.g. tests), walk beans ourselves and rebuild
        // findings with the same id scheme used by the scanner.
        if (loadClass(HANDLER_MAPPING_CLASS) == null) {
            for (Finding f : locateOnRescanFallback()) {
                if (f.id != null && f.id.equals(findingId)) return f;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private List<Finding> locateOnRescanFallback() {
        List<Finding> result = new ArrayList<>();
        java.util.Set<String> seenIds = new java.util.HashSet<>();
        Map<String, ?> beans = getBeansOfType(Object.class);
        if (beans == null) return result;
        for (Object mappingBean : beans.values()) {
            Object adapted = ReflectUtil.tryReadField(mappingBean, "adaptedInterceptors").orElse(null);
            if (!(adapted instanceof Collection)) continue;
            for (Object interceptor : (Collection<Object>) adapted) {
                if (interceptor == null) continue;
                Class<?> clazz = interceptor.getClass();
                String id = com.memhunter.agent.util.FindingIdGenerator.generate(
                        "spring-interceptor", clazz.getName(), "");
                if (!seenIds.add(id)) continue;
                Finding f = new Finding();
                f.type = "spring-interceptor";
                f.name = clazz.getSimpleName();
                f.className = clazz.getName();
                f.id = id;
                result.add(f);
            }
        }
        return result;
    }

    @Override
    protected Map<String, Object> buildDetails(Finding finding) {
        Map<String, Object> d = new HashMap<>();
        Object include = finding.attributes.get("includePatterns");
        if (include != null) d.put("includePatterns", include);
        Object exclude = finding.attributes.get("excludePatterns");
        if (exclude != null) d.put("excludePatterns", exclude);
        return d;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void doPhaseB(Finding finding) {
        InterceptorBackup b = new InterceptorBackup();
        b.targetClassName = finding.className;

        Class<?> mappingClass = loadClass(HANDLER_MAPPING_CLASS);
        Map<String, ?> beans = (mappingClass == null) ? getBeansOfType(Object.class)
                                                      : getBeansOfType(mappingClass);
        if (beans != null) {
            for (Object mappingBean : beans.values()) {
                Object adapted = ReflectUtil.tryReadField(mappingBean, "adaptedInterceptors").orElse(null);
                if (!(adapted instanceof Collection)) continue;
                Collection<Object> interceptors = (Collection<Object>) adapted;
                boolean hasTarget = false;
                for (Object i : interceptors) {
                    if (i != null && i.getClass().getName().equals(finding.className)) {
                        hasTarget = true;
                        break;
                    }
                }
                if (hasTarget) {
                    b.affected.add(new AffectedBean(mappingBean, new ArrayList<>(interceptors)));
                }
            }
        }
        this.currentBackup = b;
        this.rollback = new InterceptorRollbackStrategy(b);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void doPhaseC() throws CleanExecutionException {
        if (currentBackup.affected.isEmpty()) {
            throw new CleanExecutionException("interceptor not located during Phase B", false);
        }
        try {
            for (AffectedBean ab : currentBackup.affected) {
                Object adapted = ReflectUtil.tryReadField(ab.mappingBean, "adaptedInterceptors").orElse(null);
                if (!(adapted instanceof Collection)) continue;
                Collection<Object> current = (Collection<Object>) adapted;
                List<Object> kept = new ArrayList<>();
                for (Object i : current) {
                    if (i == null || !i.getClass().getName().equals(currentBackup.targetClassName)) {
                        kept.add(i);
                    }
                }
                ReflectUtil.setField(ab.mappingBean, "adaptedInterceptors", kept);
            }
            hookAfterPhaseC.run();
        } catch (Throwable t) {
            try { rollback.restore(); }
            catch (RollbackFailedException rf) { throw rf; }
            throw new CleanExecutionException("Phase C forward step failed", t, true);
        }
    }

    @Override
    protected List<String> phaseDLabels() {
        return Arrays.asList("phase-D: no-release-method");
    }

    @Override
    protected boolean stillPresentOnRescan(String findingId) {
        return locateOnRescan(findingId) != null;
    }

    @Override
    protected List<String> phaseSteps() {
        return Arrays.asList(
            "backup adaptedInterceptors across affected mapping beans",
            "remove target interceptor from each adaptedInterceptors list",
            "re-scan to verify");
    }

    public InterceptorBackup getCurrentBackup() { return currentBackup; }

    public static class AffectedBean {
        public final Object mappingBean;
        public final List<Object> originalList;
        public AffectedBean(Object mappingBean, List<Object> originalList) {
            this.mappingBean = mappingBean;
            this.originalList = originalList;
        }
    }

    public static class InterceptorBackup {
        public String targetClassName;
        public final List<AffectedBean> affected = new ArrayList<>();
    }

    private static class InterceptorRollbackStrategy implements RollbackStrategy {
        private final InterceptorBackup b;
        InterceptorRollbackStrategy(InterceptorBackup b) { this.b = b; }
        @Override public void restore() throws RollbackFailedException {
            try {
                for (AffectedBean ab : b.affected) {
                    ReflectUtil.setField(ab.mappingBean, "adaptedInterceptors",
                        new ArrayList<>(ab.originalList));
                }
            } catch (Throwable t) {
                throw new RollbackFailedException("interceptor rollback failed", t);
            }
        }
    }
}
