package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatServletScanner;
import com.memhunter.agent.util.ReflectUtil;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TomcatServletCleaner extends AbstractTomcatCleaner {

    private ServletBackup currentBackup;
    Runnable hookAfterChildrenWrite = () -> {};

    public TomcatServletCleaner(Object standardContext) {
        super(standardContext);
    }

    @Override
    protected boolean supportsType(String type) {
        return "tomcat-servlet".equals(type);
    }

    @Override
    protected Finding locateOnRescan(String findingId) {
        List<Finding> findings = new TomcatServletScanner(standardContext).scan(new ScanReport());
        for (Finding f : findings) {
            if (f.id != null && f.id.equals(findingId)) return f;
        }
        return null;
    }

    @Override
    protected Map<String, Object> buildDetails(Finding finding) {
        Map<String, Object> d = new HashMap<>();
        Object mappings = finding.attributes.get("mappings");
        if (mappings != null) d.put("mappings", mappings);
        Object los = finding.attributes.get("loadOnStartup");
        if (los != null) d.put("loadOnStartup", los);
        return d;
    }

    @Override
    @SuppressWarnings({"unchecked", "rawtypes"})
    protected void doPhaseB(Finding finding) {
        ServletBackup b = new ServletBackup();
        b.targetName = finding.name;

        Object childrenRaw = ReflectUtil.tryReadField(standardContext, "children").orElse(null);
        if (childrenRaw instanceof Map) {
            Map<String, Object> children = (Map<String, Object>) childrenRaw;
            b.originalWrapper = children.get(finding.name);
            b.originalChildren = new HashMap<>(children);
        }

        Object mappingsRaw = ReflectUtil.tryReadField(standardContext, "servletMappings").orElse(null);
        if (mappingsRaw instanceof Map) {
            Map<String, String> sm = (Map<String, String>) mappingsRaw;
            b.originalServletMappings = new HashMap<>(sm);
        }

        this.currentBackup = b;
        this.rollback = new ServletRollbackStrategy(standardContext, b);
    }

    @Override
    @SuppressWarnings({"unchecked", "rawtypes"})
    protected void doPhaseC() throws CleanExecutionException {
        try {
            Object childrenRaw = ReflectUtil.tryReadField(standardContext, "children").orElse(null);
            if (childrenRaw instanceof Map) {
                Map<String, Object> copy = new HashMap<>((Map) childrenRaw);
                copy.remove(currentBackup.targetName);
                ReflectUtil.setField(standardContext, "children", copy);
            }
            hookAfterChildrenWrite.run();

            Object mappingsRaw = ReflectUtil.tryReadField(standardContext, "servletMappings").orElse(null);
            if (mappingsRaw instanceof Map) {
                Map<String, String> copy = new HashMap<>((Map) mappingsRaw);
                copy.entrySet().removeIf(e -> currentBackup.targetName.equals(e.getValue()));
                ReflectUtil.setField(standardContext, "servletMappings", copy);
            }
        } catch (Throwable t) {
            try { rollback.restore(); }
            catch (RollbackFailedException rf) { throw rf; }
            throw new CleanExecutionException("Phase C forward step failed", t, true);
        }
    }

    @Override
    protected List<String> phaseDLabels() {
        Object wrapper = currentBackup == null ? null : currentBackup.originalWrapper;
        String unloadLabel = releaseTargetByConvention(wrapper, "unload");
        Object servlet = wrapper == null ? null
            : ReflectUtil.tryInvoke(wrapper, "getServlet").orElse(null);
        String destroyLabel = releaseTargetByConvention(servlet, "destroy");
        return Arrays.asList(unloadLabel, destroyLabel);
    }

    @Override
    protected boolean stillPresentOnRescan(String findingId) {
        return locateOnRescan(findingId) != null;
    }

    @Override
    protected List<String> phaseSteps() {
        return Arrays.asList(
            "backup children + servletMappings",
            "remove from children",
            "remove from servletMappings",
            "call wrapper.unload + servlet.destroy",
            "re-scan to verify");
    }

    public ServletBackup getCurrentBackup() { return currentBackup; }

    public static class ServletBackup {
        public String targetName;
        public Object originalWrapper;
        public Map<String, Object> originalChildren;
        public Map<String, String> originalServletMappings;
    }

    private static class ServletRollbackStrategy implements RollbackStrategy {
        private final Object ctx;
        private final ServletBackup b;
        ServletRollbackStrategy(Object ctx, ServletBackup b) { this.ctx = ctx; this.b = b; }
        @Override public void restore() throws RollbackFailedException {
            try {
                if (b.originalServletMappings != null) {
                    ReflectUtil.setField(ctx, "servletMappings", new HashMap<>(b.originalServletMappings));
                }
                if (b.originalChildren != null) {
                    ReflectUtil.setField(ctx, "children", new HashMap<>(b.originalChildren));
                }
            } catch (Throwable t) {
                throw new RollbackFailedException("servlet rollback failed", t);
            }
        }
    }
}
