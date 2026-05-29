package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.spring.SpringMappingScanner;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SpringMappingCleaner extends AbstractSpringCleaner {

    private static final String HANDLER_MAPPING_CLASS =
            "org.springframework.web.servlet.handler.AbstractHandlerMethodMapping";

    private MappingBackup currentBackup;
    Runnable hookAfterPhaseC = () -> {};

    public SpringMappingCleaner(Object applicationContext) {
        super(applicationContext);
    }

    @Override
    protected boolean supportsType(String type) {
        return "spring-mapping".equals(type);
    }

    @Override
    protected Finding locateOnRescan(String findingId) {
        // Preferred path: canonical scanner (real Spring runtime).
        List<Finding> findings = new SpringMappingScanner(applicationContext).scan(new ScanReport());
        for (Finding f : findings) {
            if (f.id != null && f.id.equals(findingId)) return f;
        }
        // Fallback when AbstractHandlerMethodMapping not loadable (tests / exotic classloaders).
        if (loadClass(HANDLER_MAPPING_CLASS) == null) {
            for (Finding f : locateOnRescanFallback()) {
                if (f.id != null && f.id.equals(findingId)) return f;
            }
        }
        return null;
    }

    private List<Finding> locateOnRescanFallback() {
        List<Finding> result = new ArrayList<>();
        Map<String, ?> beans = getBeansOfType(Object.class);
        if (beans == null) return result;
        for (Map.Entry<String, ?> be : beans.entrySet()) {
            String mappingBeanName = be.getKey();
            Object mappingBean = be.getValue();
            Object hmObj = ReflectUtil.tryInvoke(mappingBean, "getHandlerMethods").orElse(null);
            if (!(hmObj instanceof Map)) continue;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) hmObj).entrySet()) {
                Object info = e.getKey();
                Object handlerMethod = e.getValue();
                Object beanType = ReflectUtil.tryInvoke(handlerMethod, "getBeanType").orElse(null);
                String className = (beanType instanceof Class) ? ((Class<?>) beanType).getName()
                                                               : String.valueOf(beanType);
                Object method = ReflectUtil.tryInvoke(handlerMethod, "getMethod").orElse(null);
                String methodName = (method instanceof Method) ? ((Method) method).getName() : "";
                Finding f = new Finding();
                f.type = "spring-mapping";
                f.className = className;
                f.name = mappingBeanName + "#" + methodName;
                f.attributes.put("pattern", String.valueOf(info));
                f.id = FindingIdGenerator.generate("spring-mapping", className, String.valueOf(info));
                result.add(f);
            }
        }
        return result;
    }

    @Override
    protected Map<String, Object> buildDetails(Finding finding) {
        Map<String, Object> d = new HashMap<>();
        Object pattern = finding.attributes.get("pattern");
        if (pattern != null) d.put("pattern", pattern);
        Object handlerMethod = finding.attributes.get("handlerMethod");
        if (handlerMethod != null) d.put("handlerMethod", handlerMethod);
        return d;
    }

    @Override
    protected void doPhaseB(Finding finding) {
        MappingBackup b = new MappingBackup();
        String wantPattern = String.valueOf(finding.attributes.get("pattern"));
        String wantClass = finding.className;

        Class<?> mappingClass = loadClass(HANDLER_MAPPING_CLASS);
        Map<String, ?> beans = (mappingClass == null) ? getBeansOfType(Object.class)
                                                      : getBeansOfType(mappingClass);
        if (beans != null) {
            outer:
            for (Object mappingBean : beans.values()) {
                Object hmObj = ReflectUtil.tryInvoke(mappingBean, "getHandlerMethods").orElse(null);
                if (!(hmObj instanceof Map)) continue;
                for (Map.Entry<?, ?> e : ((Map<?, ?>) hmObj).entrySet()) {
                    Object info = e.getKey();
                    Object handlerMethod = e.getValue();
                    if (!String.valueOf(info).equals(wantPattern)) continue;
                    Object beanType = ReflectUtil.tryInvoke(handlerMethod, "getBeanType").orElse(null);
                    String btName = (beanType instanceof Class) ? ((Class<?>) beanType).getName()
                                                                : String.valueOf(beanType);
                    if (!btName.equals(wantClass)) continue;
                    b.mappingBean = mappingBean;
                    b.info = info;
                    b.handlerMethod = handlerMethod;
                    // Prefer the real handler bean instance for registerMapping rollback;
                    // fall back to the bean type (Class) if getBean() is unavailable.
                    Object handlerBean = ReflectUtil.tryInvoke(handlerMethod, "getBean").orElse(beanType);
                    b.handlerBean = handlerBean;
                    Object method = ReflectUtil.tryInvoke(handlerMethod, "getMethod").orElse(null);
                    b.method = (method instanceof Method) ? (Method) method : null;
                    break outer;
                }
            }
        }
        this.currentBackup = b;
        this.rollback = new MappingRollbackStrategy(b);
    }

    @Override
    protected void doPhaseC() throws CleanExecutionException {
        if (currentBackup.mappingBean == null || currentBackup.info == null) {
            throw new CleanExecutionException("mapping not located during Phase B", false);
        }
        // Step 1: unregister — the sole mutation. If this fails, nothing was
        // removed, so there is nothing to roll back (didMutate=false).
        try {
            Method m = findMethod(currentBackup.mappingBean.getClass(), "unregisterMapping", 1);
            if (m == null) throw new NoSuchMethodException("unregisterMapping not found");
            m.invoke(currentBackup.mappingBean, currentBackup.info);
        } catch (Throwable t) {
            throw new CleanExecutionException("unregisterMapping failed", t, false);
        }
        // Step 2: post-mutation hook (test seam). A failure here means the
        // unregister already succeeded, so roll back (didMutate=true).
        try {
            hookAfterPhaseC.run();
        } catch (Throwable t) {
            try { rollback.restore(); }
            catch (RollbackFailedException rf) { throw rf; }
            throw new CleanExecutionException("Phase C post-step failed", t, true);
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
            "backup mapping bean + RequestMappingInfo + HandlerMethod",
            "call mapping.unregisterMapping(info)",
            "re-scan to verify");
    }

    public MappingBackup getCurrentBackup() { return currentBackup; }

    private static Method findMethod(Class<?> c, String name, int paramCount) {
        for (Method m : c.getMethods()) {
            if (m.getName().equals(name) && m.getParameterCount() == paramCount) return m;
        }
        return null;
    }

    public static class MappingBackup {
        public Object mappingBean;
        public Object info;
        public Object handlerMethod;
        public Object handlerBean;
        public Method method;
    }

    private static class MappingRollbackStrategy implements RollbackStrategy {
        private final MappingBackup b;
        MappingRollbackStrategy(MappingBackup b) { this.b = b; }
        @Override public void restore() throws RollbackFailedException {
            try {
                if (b.mappingBean == null || b.info == null) return;
                Method reg = findMethod(b.mappingBean.getClass(), "registerMapping", 3);
                if (reg == null) throw new NoSuchMethodException("registerMapping not found");
                reg.invoke(b.mappingBean, b.info, b.handlerBean, b.method);
            } catch (Throwable t) {
                throw new RollbackFailedException("mapping rollback failed", t);
            }
        }
    }
}
