package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatValveScanner;
import com.memhunter.agent.util.ReflectUtil;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TomcatValveCleaner extends AbstractTomcatCleaner {

    private ValveBackup currentBackup;
    Runnable hookAfterPipelineWrite = () -> {};

    public TomcatValveCleaner(Object standardContext) {
        super(standardContext);
    }

    @Override
    protected boolean supportsType(String type) {
        return "tomcat-valve".equals(type);
    }

    @Override
    protected Finding locateOnRescan(String findingId) {
        List<Finding> findings = new TomcatValveScanner(standardContext).scan(new ScanReport());
        for (Finding f : findings) {
            if (f.id != null && f.id.equals(findingId)) return f;
        }
        return null;
    }

    @Override
    protected Map<String, Object> buildDetails(Finding finding) {
        Map<String, Object> d = new HashMap<>();
        Object idx = finding.attributes.get("pipelineIndex");
        if (idx != null) d.put("pipelineIndex", idx);
        Object level = finding.attributes.get("containerLevel");
        if (level != null) d.put("containerLevel", level);
        return d;
    }

    @Override
    protected void doPhaseB(Finding finding) {
        ValveBackup b = new ValveBackup();
        Object pipeline = ReflectUtil.tryInvoke(standardContext, "getPipeline").orElse(null);
        if (pipeline == null) {
            b.pipeline = null;
            this.currentBackup = b;
            this.rollback = new ValveRollbackStrategy(b);
            return;
        }
        b.pipeline = pipeline;
        b.targetClassName = finding.className;

        Object first = ReflectUtil.tryInvoke(pipeline, "getFirst").orElse(null);
        b.originalFirst = first;
        Object prev = null;
        Object cur = first;
        Set<Object> visited = new HashSet<>();
        int hardStop = 0;
        while (cur != null && visited.add(cur) && hardStop++ < 200) {
            if (cur.getClass().getName().equals(b.targetClassName)) {
                b.target = cur;
                b.prev = prev;
                b.targetNext = ReflectUtil.tryInvoke(cur, "getNext").orElse(null);
                break;
            }
            prev = cur;
            cur = ReflectUtil.tryInvoke(cur, "getNext").orElse(null);
        }

        this.currentBackup = b;
        this.rollback = new ValveRollbackStrategy(b);
    }

    @Override
    protected void doPhaseC() throws CleanExecutionException {
        try {
            if (currentBackup.target == null) {
                throw new IllegalStateException("target valve not located during Phase B");
            }
            if (currentBackup.prev == null) {
                // target was first; reassign pipeline.first via reflection
                ReflectUtil.setField(currentBackup.pipeline, "first", currentBackup.targetNext);
            } else {
                // prev.setNext(targetNext) via reflection
                Method setNext = null;
                for (Method m : currentBackup.prev.getClass().getMethods()) {
                    if ("setNext".equals(m.getName()) && m.getParameterCount() == 1) {
                        setNext = m;
                        break;
                    }
                }
                if (setNext == null) {
                    throw new RuntimeException("setNext not found on prev");
                }
                setNext.invoke(currentBackup.prev, currentBackup.targetNext);
            }
            hookAfterPipelineWrite.run();
        } catch (Throwable t) {
            try { rollback.restore(); }
            catch (RollbackFailedException rf) { throw rf; }
            throw new CleanExecutionException("Phase C forward step failed", t);
        }
    }

    @Override
    protected List<String> phaseDLabels() {
        Object target = currentBackup == null ? null : currentBackup.target;
        return Arrays.asList(releaseTargetByConvention(target, "stop"));
    }

    @Override
    protected boolean stillPresentOnRescan(String findingId) {
        return locateOnRescan(findingId) != null;
    }

    @Override
    protected List<String> phaseSteps() {
        return Arrays.asList(
            "backup pipeline links (prev/target/next)",
            "relink prev.setNext(next) OR pipeline.first = next",
            "call valve.stop()",
            "re-scan to verify");
    }

    public ValveBackup getCurrentBackup() { return currentBackup; }

    public static class ValveBackup {
        public Object pipeline;
        public Object originalFirst;
        public Object prev;     // null if target was first
        public Object target;
        public Object targetNext;
        public String targetClassName;
    }

    private static class ValveRollbackStrategy implements RollbackStrategy {
        private final ValveBackup b;
        ValveRollbackStrategy(ValveBackup b) { this.b = b; }
        @Override public void restore() throws RollbackFailedException {
            try {
                if (b.pipeline == null || b.target == null) return;
                if (b.prev == null) {
                    ReflectUtil.setField(b.pipeline, "first", b.originalFirst);
                } else {
                    Method setNext = null;
                    for (Method m : b.prev.getClass().getMethods()) {
                        if ("setNext".equals(m.getName()) && m.getParameterCount() == 1) {
                            setNext = m;
                            break;
                        }
                    }
                    if (setNext == null) {
                        throw new RuntimeException("setNext not found on prev for rollback");
                    }
                    setNext.invoke(b.prev, b.target);
                }
            } catch (Throwable t) {
                throw new RollbackFailedException("valve rollback failed", t);
            }
        }
    }
}
