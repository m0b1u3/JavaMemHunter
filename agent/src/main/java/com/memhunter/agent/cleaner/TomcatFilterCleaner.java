package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.FilterBackup;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scanner.tomcat.TomcatFilterScanner;
import com.memhunter.agent.util.ReflectUtil;

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

    public TomcatFilterCleaner(Object standardContext) {
        this.standardContext = standardContext;
    }

    public FilterBackup getCurrentBackup() {
        return currentBackup;
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
        throw new UnsupportedOperationException("Phase C/D/E lands in Task 5/6");
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
