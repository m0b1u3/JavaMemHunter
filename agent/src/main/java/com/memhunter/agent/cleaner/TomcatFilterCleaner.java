package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.FilterBackup;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatFilterScanner;
import com.memhunter.agent.util.ReflectUtil;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TomcatFilterCleaner implements Cleaner {

    private static final String TYPE = "tomcat-filter";
    private static final int SCORE_THRESHOLD = 7;

    private final Object standardContext;
    private FilterBackup currentBackup;
    private String currentFilterName;

    // Test instrumentation: invoked after Phase C step 1 (configs write), before step 2 (maps).
    // Package-private setter used only by Phase C failure-path tests.
    Runnable hookAfterConfigsWrite = () -> {};

    // Test instrumentation: invoked after Phase C completes successfully, before Phase D.
    // Used by full-flow tests to simulate verify failure (e.g. re-insert filter to mimic
    // Tomcat caching the reference elsewhere).
    Runnable hookAfterPhaseC = () -> {};

    public TomcatFilterCleaner(Object standardContext) {
        this.standardContext = standardContext;
    }

    public FilterBackup getCurrentBackup() {
        return currentBackup;
    }

    public String getCurrentFilterName() {
        return currentFilterName;
    }

    @Override
    public CleanPlan plan(Finding finding, boolean forced) {
        if (finding == null) return null;
        if (!TYPE.equals(finding.type)) return null;
        if (finding.score < SCORE_THRESHOLD && !forced) return null;

        // Phase A: re-scan and locate finding by id
        TomcatFilterScanner scanner = new TomcatFilterScanner(standardContext);
        List<Finding> rescanned = scanner.scan(new ScanReport());
        Finding located = null;
        for (Finding f : rescanned) {
            if (f.id != null && f.id.equals(finding.id)) {
                located = f;
                break;
            }
        }
        if (located == null) return null;

        // Phase B: snapshot
        String filterName = finding.name;
        FilterBackup backup = new FilterBackup();

        Map<?, ?> filterDefs = asMap(ReflectUtil.tryReadField(standardContext, "filterDefs").orElse(null));
        backup.originalFilterDef = filterDefs.get(filterName);

        Object[] filterMapsArr = asArray(ReflectUtil.tryReadField(standardContext, "filterMaps").orElse(null));
        List<Object> matchingMaps = new ArrayList<>();
        for (Object map : filterMapsArr) {
            if (map == null) continue;
            Object name = ReflectUtil.tryReadField(map, "filterName").orElse(null);
            if (filterName.equals(name)) {
                matchingMaps.add(map);
            }
        }
        backup.originalFilterMaps = matchingMaps;

        Map<?, ?> filterConfigs = asMap(ReflectUtil.tryReadField(standardContext, "filterConfigs").orElse(null));
        backup.originalFilterConfig = filterConfigs.get(filterName);
        Map<String, Object> configsCopy = new HashMap<>();
        for (Map.Entry<?, ?> e : filterConfigs.entrySet()) {
            configsCopy.put(String.valueOf(e.getKey()), e.getValue());
        }
        backup.originalFilterConfigsMap = configsCopy;

        this.currentBackup = backup;
        this.currentFilterName = filterName;

        // Build plan
        CleanPlan plan = new CleanPlan();
        plan.findingId = finding.id;
        plan.type = finding.type;
        plan.filterName = filterName;
        plan.filterClass = finding.className;
        plan.urlPatterns = extractUrlPatterns(finding);
        plan.contextPath = extractContextPath(finding);
        plan.score = finding.score;
        plan.level = finding.level;
        plan.forced = forced;
        plan.steps = Arrays.asList(
                "backup filterDef/filterMap/filterConfig",
                "remove from filterConfigs",
                "remove from filterMaps",
                "remove from filterDefs",
                "call filter.destroy()",
                "re-scan to verify"
        );
        plan.rollbackSupported = true;
        plan.generatedAt = System.currentTimeMillis();
        return plan;
    }

    @Override
    public CleanResult execute(CleanPlan plan, boolean forced) {
        CleanResult result = new CleanResult();
        result.findingId = plan == null ? null : plan.findingId;
        result.executedAt = System.currentTimeMillis();
        result.executedSteps = new ArrayList<>();

        if (plan == null) {
            result.failureReason = "clean plan is required";
            return result;
        }
        if (currentBackup == null || currentFilterName == null) {
            result.failureReason = "plan() must be called before execute()";
            return result;
        }

        try {
            doPhaseC();
            result.executedSteps.add("phase-C: removed filter registrations");
            hookAfterPhaseC.run();

            result.executedSteps.add(releaseOriginalFilterConfig());

            if (isFindingStillPresent(plan.findingId)) {
                new RollbackManager().restore(standardContext, currentFilterName, currentBackup);
                result.rolledBack = true;
                result.verifiedDisappeared = false;
                result.failureReason = "verify failed: finding still present after clean";
                result.executedSteps.add("phase-E: verify failed; rolled back");
                return result;
            }

            result.success = true;
            result.verifiedDisappeared = true;
            result.executedSteps.add("phase-E: verified disappeared");
            return result;
        } catch (CleanExecutionException e) {
            result.rolledBack = true;
            result.failureReason = e.getMessage();
            result.executedSteps.add("phase-C: failed; rolled back");
            return result;
        } catch (RollbackFailedException e) {
            result.rolledBack = false;
            result.failureReason = e.getMessage();
            result.executedSteps.add("rollback failed");
            return result;
        } catch (Throwable t) {
            result.failureReason = t.getMessage();
            return result;
        }
    }

    private String releaseOriginalFilterConfig() {
        Object config = currentBackup == null ? null : currentBackup.originalFilterConfig;
        if (config == null) {
            // Null config (e.g. backup never captured one) is deliberately collapsed
            // with NoSuchMethodException onto the same label. Both mean "release()
            // was not invoked"; the runtime mutation already detached the filter.
            return "phase-D: no-release-method";
        }
        try {
            // getMethod is intentional: ApplicationFilterConfig.release() is public.
            // We do not probe non-public declared methods; if a subclass downgrades
            // release() to package-private, this falls through to no-release-method.
            java.lang.reflect.Method m = config.getClass().getMethod("release");
            m.invoke(config);
            return "phase-D: destroy-ran";
        } catch (NoSuchMethodException nsme) {
            return "phase-D: no-release-method";
        } catch (java.lang.reflect.InvocationTargetException ite) {
            Throwable cause = ite.getCause() != null ? ite.getCause() : ite;
            return phaseDThrew(cause);
        } catch (Throwable t) {
            return phaseDThrew(t);
        }
    }

    private static String phaseDThrew(Throwable t) {
        String msg = t.getMessage() == null ? "" : t.getMessage();
        return "phase-D: destroy-threw: " + t.getClass().getSimpleName() + ": " + msg;
    }

    private boolean isFindingStillPresent(String findingId) {
        TomcatFilterScanner scanner = new TomcatFilterScanner(standardContext);
        List<Finding> findings = scanner.scan(new ScanReport());
        for (Finding f : findings) {
            if (f != null && findingId != null && findingId.equals(f.id)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Phase C: atomic copy-replace of filterConfigs / filterMaps.array / filterDefs.
     * Order per design §5.2: configs -> maps -> defs (request path drains first).
     * On any failure, RollbackManager restores prior state and CleanExecutionException
     * is re-thrown wrapping the original cause.
     */
    @SuppressWarnings("unchecked")
    void doPhaseC() {
        if (currentBackup == null || currentFilterName == null) {
            throw new CleanExecutionException("doPhaseC called before plan()",
                    new IllegalStateException("no backup/filterName"));
        }
        String filterName = currentFilterName;
        try {
            // Step 1: filterConfigs (copy, remove, replace)
            Object configsObj = ReflectUtil.tryReadField(standardContext, "filterConfigs").orElse(null);
            Map<String, Object> newConfigs = new HashMap<>();
            if (configsObj instanceof Map) {
                for (Map.Entry<?, ?> e : ((Map<?, ?>) configsObj).entrySet()) {
                    newConfigs.put(String.valueOf(e.getKey()), e.getValue());
                }
            }
            newConfigs.remove(filterName);
            ReflectUtil.setField(standardContext, "filterConfigs", newConfigs);

            // Test hook: allow tests to inject a failure between step 1 and step 2.
            hookAfterConfigsWrite.run();

            // Step 2: filterMaps.array (filter out entries with filterName==target)
            Object mapsField = ReflectUtil.tryReadField(standardContext, "filterMaps").orElse(null);
            if (mapsField == null) {
                throw new IllegalStateException("filterMaps field is null");
            }
            Object[] currentArr;
            boolean nested;
            Object wrapper = null;
            if (mapsField instanceof Object[]) {
                currentArr = (Object[]) mapsField;
                nested = false;
            } else {
                wrapper = mapsField;
                Object arr = ReflectUtil.tryReadField(wrapper, "array").orElse(null);
                if (!(arr instanceof Object[])) {
                    throw new IllegalStateException("filterMaps.array not Object[]");
                }
                currentArr = (Object[]) arr;
                nested = true;
            }
            List<Object> kept = new ArrayList<>();
            for (Object m : currentArr) {
                if (m == null) continue;
                Object name = ReflectUtil.tryReadField(m, "filterName").orElse(null);
                if (!filterName.equals(name)) {
                    kept.add(m);
                }
            }
            Object[] newArr = toCompatibleArray(kept, currentArr);
            if (nested) {
                ReflectUtil.setField(wrapper, "array", newArr);
            } else {
                ReflectUtil.setField(standardContext, "filterMaps", newArr);
            }

            // Step 3: filterDefs (copy, remove, replace)
            Object defsObj = ReflectUtil.tryReadField(standardContext, "filterDefs").orElse(null);
            Map<String, Object> newDefs = new HashMap<>();
            if (defsObj instanceof Map) {
                for (Map.Entry<?, ?> e : ((Map<?, ?>) defsObj).entrySet()) {
                    newDefs.put(String.valueOf(e.getKey()), e.getValue());
                }
            }
            newDefs.remove(filterName);
            ReflectUtil.setField(standardContext, "filterDefs", newDefs);
        } catch (Throwable forward) {
            // Best-effort rollback; if rollback also fails, surface the rollback failure.
            try {
                new RollbackManager().restore(standardContext, filterName, currentBackup);
            } catch (RollbackFailedException rbf) {
                throw rbf;
            } catch (Throwable rbt) {
                throw new RollbackFailedException("rollback failed after forward failure", rbt);
            }
            throw new CleanExecutionException("Phase C failed; rolled back", forward);
        }
    }

    private Object[] toCompatibleArray(List<Object> values, Object[] originalArray) {
        Class<?> componentType = Object.class;
        if (originalArray != null && originalArray.getClass().isArray()) {
            componentType = originalArray.getClass().getComponentType();
        }
        Object typed = Array.newInstance(componentType, values.size());
        for (int i = 0; i < values.size(); i++) {
            Array.set(typed, i, values.get(i));
        }
        return (Object[]) typed;
    }

    @SuppressWarnings("unchecked")
    private List<String> extractUrlPatterns(Finding finding) {
        Object v = finding.attributes.get("urlPatterns");
        if (v instanceof List) return (List<String>) v;
        return new ArrayList<>();
    }

    private String extractContextPath(Finding finding) {
        Object v = finding.attributes.get("contextPath");
        return v == null ? "" : String.valueOf(v);
    }

    private Map<?, ?> asMap(Object v) {
        return (v instanceof Map) ? (Map<?, ?>) v : new HashMap<>();
    }

    private Object[] asArray(Object v) {
        if (v instanceof Object[]) return (Object[]) v;
        Object nested = ReflectUtil.tryReadAnyOf(v, "array", "filterMaps").orElse(null);
        return (nested instanceof Object[]) ? (Object[]) nested : new Object[0];
    }
}
