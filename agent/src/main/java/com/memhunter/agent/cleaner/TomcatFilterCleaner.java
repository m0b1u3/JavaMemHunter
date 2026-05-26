package com.memhunter.agent.cleaner;

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

/**
 * v0.7 TomcatFilterCleaner — refactored to extend AbstractTomcatCleaner.
 * Phase A/D/E come from the base template; this subclass implements
 * Phase B (snapshot filterDefs/filterMaps/filterConfigs) and Phase C
 * (atomic copy-replace), and adapts the new CleanPlan schema
 * (targetName/targetClass/details).
 */
public class TomcatFilterCleaner extends AbstractTomcatCleaner {

    private static final String TYPE = "tomcat-filter";

    private FilterBackup currentBackup;

    // Test instrumentation hooks (package-private, preserved from v0.6).
    Runnable hookAfterConfigsWrite = () -> {};
    Runnable hookAfterPhaseC = () -> {};

    public TomcatFilterCleaner(Object standardContext) {
        super(standardContext);
    }

    public FilterBackup getCurrentBackup() {
        return currentBackup;
    }

    public String getCurrentFilterName() {
        return currentTargetName;
    }

    @Override
    protected boolean supportsType(String type) {
        return TYPE.equals(type);
    }

    @Override
    protected Finding locateOnRescan(String findingId) {
        TomcatFilterScanner scanner = new TomcatFilterScanner(standardContext);
        List<Finding> rescanned = scanner.scan(new ScanReport());
        for (Finding f : rescanned) {
            if (f.id != null && f.id.equals(findingId)) return f;
        }
        return null;
    }

    @Override
    protected Map<String, Object> buildDetails(Finding finding) {
        Map<String, Object> d = new HashMap<>();
        Object urls = finding.attributes.get("urlPatterns");
        if (urls != null) d.put("urlPatterns", urls);
        Object disps = finding.attributes.get("dispatcherTypes");
        if (disps != null) d.put("dispatcherTypes", disps);
        return d;
    }

    @Override
    protected void doPhaseB(Finding finding) {
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
        this.rollback = new FilterRollbackStrategy(standardContext, filterName, backup);
    }

    @Override
    protected List<String> phaseSteps() {
        return Arrays.asList(
                "backup filterDef/filterMap/filterConfig",
                "remove from filterConfigs",
                "remove from filterMaps",
                "remove from filterDefs",
                "call filter.destroy()",
                "re-scan to verify"
        );
    }

    /**
     * Phase C: atomic copy-replace of filterConfigs / filterMaps.array / filterDefs.
     * Order: configs -> maps -> defs (request path drains first).
     * On any failure, rollback via FilterRollbackStrategy and rethrow as
     * CleanExecutionException so the base template surfaces "Phase C failed".
     *
     * Package-private visibility preserved so PhaseCTest can invoke doPhaseC() directly.
     */
    @Override
    @SuppressWarnings("unchecked")
    protected void doPhaseC() throws CleanExecutionException {
        if (currentBackup == null || currentTargetName == null) {
            throw new CleanExecutionException("doPhaseC called before plan()",
                    new IllegalStateException("no backup/filterName"));
        }
        String filterName = currentTargetName;
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

            hookAfterConfigsWrite.run();

            // Step 2: filterMaps.array
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

            // Step 3: filterDefs
            Object defsObj = ReflectUtil.tryReadField(standardContext, "filterDefs").orElse(null);
            Map<String, Object> newDefs = new HashMap<>();
            if (defsObj instanceof Map) {
                for (Map.Entry<?, ?> e : ((Map<?, ?>) defsObj).entrySet()) {
                    newDefs.put(String.valueOf(e.getKey()), e.getValue());
                }
            }
            newDefs.remove(filterName);
            ReflectUtil.setField(standardContext, "filterDefs", newDefs);

            hookAfterPhaseC.run();
        } catch (Throwable forward) {
            // Best-effort rollback via the captured strategy.
            try {
                rollback.restore();
            } catch (RollbackFailedException rbf) {
                throw rbf;
            } catch (Throwable rbt) {
                throw new RollbackFailedException("rollback failed after forward failure", rbt);
            }
            throw new CleanExecutionException("Phase C failed; rolled back", forward);
        }
    }

    @Override
    protected List<String> phaseDLabels() {
        Object cfg = currentBackup == null ? null : currentBackup.originalFilterConfig;
        return Arrays.asList(releaseTargetByConvention(cfg, "release"));
    }

    @Override
    protected boolean stillPresentOnRescan(String findingId) {
        return locateOnRescan(findingId) != null;
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

    private Map<?, ?> asMap(Object v) {
        return (v instanceof Map) ? (Map<?, ?>) v : new HashMap<>();
    }

    private Object[] asArray(Object v) {
        if (v instanceof Object[]) return (Object[]) v;
        Object nested = ReflectUtil.tryReadAnyOf(v, "array", "filterMaps").orElse(null);
        return (nested instanceof Object[]) ? (Object[]) nested : new Object[0];
    }
}
