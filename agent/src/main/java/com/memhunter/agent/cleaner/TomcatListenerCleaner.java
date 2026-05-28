package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatListenerScanner;
import com.memhunter.agent.util.ReflectUtil;

import java.lang.reflect.Method;
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
        Object[] events = eventListeners();
        Object[] lifes = lifecycleListeners();
        b.originalEvents = events == null ? null : events.clone();
        b.originalLifecycles = lifes == null ? null : lifes.clone();
        b.targetClassName = finding.className;
        this.currentBackup = b;
        this.rollback = new ListenerRollbackStrategy(standardContext, b);
    }

    @Override
    protected void doPhaseC() throws CleanExecutionException {
        try {
            Object[] events = eventListeners();
            if (events != null) {
                Object[] filtered = filterOutByClassName(events, currentBackup.targetClassName);
                setEventListeners(filtered);
            }
            hookAfterEventWrite.run();

            Object[] lifes = lifecycleListeners();
            if (lifes != null) {
                Object[] filtered = filterOutByClassName(lifes, currentBackup.targetClassName);
                setLifecycleListeners(filtered);
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

    private Object[] eventListeners() {
        Object viaGetter = ReflectUtil.tryInvoke(standardContext, "getApplicationEventListeners")
            .orElse(null);
        if (viaGetter != null) return toArray(viaGetter);
        return toArray(ReflectUtil.tryReadAnyOf(standardContext,
            "applicationEventListeners",
            "applicationEventListenersList").orElse(null));
    }

    private Object[] lifecycleListeners() {
        Object viaGetter = ReflectUtil.tryInvoke(standardContext, "getApplicationLifecycleListeners")
            .orElse(null);
        if (viaGetter != null) return toArray(viaGetter);
        return toArray(ReflectUtil.tryReadAnyOf(standardContext,
            "applicationLifecycleListeners",
            "applicationLifecycleListenersObjects").orElse(null));
    }

    private static Object[] toArray(Object value) {
        if (value instanceof Object[]) return (Object[]) value;
        if (value instanceof List) return ((List<?>) value).toArray();
        return null;
    }

    private void setEventListeners(Object[] listeners) {
        if (tryInvokeSetter("setApplicationEventListeners", listeners)) return;
        if (trySetField("applicationEventListeners", listeners)) return;
        if (trySetField("applicationEventListenersList", new ArrayList<>(Arrays.asList(listeners)))) return;
        throw new RuntimeException("no writable event listener storage found");
    }

    private void setLifecycleListeners(Object[] listeners) {
        if (tryInvokeSetter("setApplicationLifecycleListeners", listeners)) return;
        if (trySetField("applicationLifecycleListeners", listeners)) return;
        if (trySetField("applicationLifecycleListenersObjects", listeners)) return;
        throw new RuntimeException("no writable lifecycle listener storage found");
    }

    private boolean tryInvokeSetter(String methodName, Object[] listeners) {
        try {
            Method m = standardContext.getClass().getMethod(methodName, Object[].class);
            m.invoke(standardContext, new Object[] { listeners });
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean trySetField(String fieldName, Object value) {
        try {
            ReflectUtil.setField(standardContext, fieldName, value);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
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
                TomcatListenerCleaner cleaner = new TomcatListenerCleaner(ctx);
                if (b.originalLifecycles != null) {
                    cleaner.setLifecycleListeners(b.originalLifecycles);
                }
                if (b.originalEvents != null) {
                    cleaner.setEventListeners(b.originalEvents);
                }
            } catch (Throwable t) {
                throw new RollbackFailedException("listener rollback failed", t);
            }
        }
    }
}
