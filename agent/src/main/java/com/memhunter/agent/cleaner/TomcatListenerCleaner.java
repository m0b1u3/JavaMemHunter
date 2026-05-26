package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatListenerScanner;
import com.memhunter.agent.util.ReflectUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TomcatListenerCleaner extends AbstractTomcatCleaner {

    private ListenerBackup currentBackup;
    Runnable hookAfterEventWrite = () -> {};

    public TomcatListenerCleaner(Object standardContext) {
        super(standardContext);
    }

    @Override
    protected boolean supportsType(String type) {
        return type != null && type.startsWith("tomcat-listener-");
    }

    @Override
    protected Finding locateOnRescan(String findingId) {
        List<Finding> findings = new TomcatListenerScanner(standardContext).scan(new ScanReport());
        for (Finding f : findings) {
            if (f.id != null && f.id.equals(findingId)) return f;
        }
        return null;
    }

    @Override
    protected Map<String, Object> buildDetails(Finding finding) {
        Map<String, Object> d = new HashMap<>();
        Object kind = finding.attributes.get("listenerKind");
        if (kind != null) d.put("listenerKind", kind);
        return d;
    }

    @Override
    protected void doPhaseB(Finding finding) {
        ListenerBackup b = new ListenerBackup();
        Object[] events = arrField("applicationEventListeners");
        Object[] lifes = arrField("applicationLifecycleListeners");
        b.originalEvents = events == null ? null : events.clone();
        b.originalLifecycles = lifes == null ? null : lifes.clone();
        b.targetClassName = finding.className;
        this.currentBackup = b;
        this.rollback = new ListenerRollbackStrategy(standardContext, b);
    }

    @Override
    protected void doPhaseC() throws CleanExecutionException {
        try {
            Object[] events = arrField("applicationEventListeners");
            if (events != null) {
                Object[] filtered = filterOutByClassName(events, currentBackup.targetClassName);
                ReflectUtil.setField(standardContext, "applicationEventListeners", filtered);
            }
            hookAfterEventWrite.run();

            Object[] lifes = arrField("applicationLifecycleListeners");
            if (lifes != null) {
                Object[] filtered = filterOutByClassName(lifes, currentBackup.targetClassName);
                ReflectUtil.setField(standardContext, "applicationLifecycleListeners", filtered);
            }
        } catch (Throwable t) {
            try { rollback.restore(); }
            catch (RollbackFailedException rf) { throw rf; }
            throw new CleanExecutionException("Phase C forward step failed", t);
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
            "backup applicationEventListeners + applicationLifecycleListeners",
            "remove from applicationEventListeners",
            "remove from applicationLifecycleListeners",
            "re-scan to verify");
    }

    private Object[] arrField(String name) {
        Object v = ReflectUtil.tryReadField(standardContext, name).orElse(null);
        return v instanceof Object[] ? (Object[]) v : null;
    }

    private static Object[] filterOutByClassName(Object[] arr, String className) {
        List<Object> kept = new ArrayList<>(arr.length);
        for (Object o : arr) {
            if (o == null) continue;
            if (!o.getClass().getName().equals(className)) kept.add(o);
        }
        return kept.toArray();
    }

    public ListenerBackup getCurrentBackup() { return currentBackup; }

    public static class ListenerBackup {
        public Object[] originalEvents;
        public Object[] originalLifecycles;
        public String targetClassName;
    }

    private static class ListenerRollbackStrategy implements RollbackStrategy {
        private final Object ctx;
        private final ListenerBackup b;
        ListenerRollbackStrategy(Object ctx, ListenerBackup b) { this.ctx = ctx; this.b = b; }
        @Override public void restore() throws RollbackFailedException {
            try {
                if (b.originalLifecycles != null) {
                    ReflectUtil.setField(ctx, "applicationLifecycleListeners", b.originalLifecycles);
                }
                if (b.originalEvents != null) {
                    ReflectUtil.setField(ctx, "applicationEventListeners", b.originalEvents);
                }
            } catch (Throwable t) {
                throw new RollbackFailedException("listener rollback failed", t);
            }
        }
    }
}
