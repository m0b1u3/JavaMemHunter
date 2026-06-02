package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class TomcatFilterScanner {

    private static final String TYPE = "tomcat-filter";
    private final Object context;

    public TomcatFilterScanner(Object context) {
        this.context = context;
    }

    public List<Finding> scan(ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        try {
            String contextPath = readContextPath(context);
            Optional<Object> defsOpt = ReflectUtil.tryReadAnyOf(context, "filterDefs");
            if (!defsOpt.isPresent()) {
                report.partialErrors.add(new ScanReport.PartialError(
                        "TomcatFilterScanner", "field filterDefs not accessible on " + contextPath));
                return findings;
            }
            Map<?, ?> filterDefs = asMap(defsOpt.get());
            Object[] filterMaps = asArray(ReflectUtil.tryReadField(context, "filterMaps").orElse(null));
            Map<?, ?> filterConfigs = asMap(ReflectUtil.tryReadField(context, "filterConfigs").orElse(null));

            for (Map.Entry<?, ?> entry : filterDefs.entrySet()) {
                String filterName = String.valueOf(entry.getKey());
                Object def = entry.getValue();
                Finding f = buildFinding(filterName, def, filterMaps, filterConfigs, contextPath);
                findings.add(f);
            }
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                    "TomcatFilterScanner", "exception: " + t.getMessage()));
        }
        return findings;
    }

    private Finding buildFinding(String filterName, Object def, Object[] filterMaps,
                                 Map<?, ?> filterConfigs, String contextPath) {
        Finding f = new Finding();
        f.type = TYPE;
        f.name = filterName;
        f.className = String.valueOf(ReflectUtil.tryReadField(def, "filterClass").orElse(null));
        f.attributes.put("filterClass", f.className);
        f.attributes.put("contextPath", contextPath);
        f.attributes.put("urlPatterns", collectUrlPatterns(filterName, filterMaps));
        f.attributes.put("dispatcherTypes", collectDispatcherTypes(filterName, filterMaps));

        Object filterInstance = extractFilterInstance(filterConfigs, filterName);
        if (filterInstance != null) {
            f.codeSource = codeSourceOf(filterInstance.getClass());
            f.classLoader = clName(filterInstance.getClass().getClassLoader());
        }

        f.id = FindingIdGenerator.generate(TYPE, f.className == null ? "" : f.className, filterName);

        // v0.10: tag isDynamic from FilterDef.dynamic field (true = addFilter() runtime registration)
        Optional<Object> dynField = ReflectUtil.tryReadField(def, "dynamic");
        boolean isDynamic = dynField.map(v -> Boolean.TRUE.equals(v)).orElse(true);
        f.attributes.put("isDynamic", isDynamic);

        return f;
    }

    private String readContextPath(Object ctx) {
        Optional<Object> path = ReflectUtil.tryInvoke(ctx, "getPath");
        return path.isPresent() ? String.valueOf(path.get()) : "";
    }

    private Map<?, ?> asMap(Object v) {
        return (v instanceof Map) ? (Map<?, ?>) v : new HashMap<>();
    }

    private Object[] asArray(Object v) {
        if (v instanceof Object[]) return (Object[]) v;
        Object nested = ReflectUtil.tryReadAnyOf(v, "array", "filterMaps").orElse(null);
        return (nested instanceof Object[]) ? (Object[]) nested : new Object[0];
    }

    private List<String> collectUrlPatterns(String filterName, Object[] filterMaps) {
        List<String> patterns = new ArrayList<>();
        for (Object map : filterMaps) {
            if (map == null) continue;
            Object name = ReflectUtil.tryReadField(map, "filterName").orElse(null);
            if (!filterName.equals(name)) continue;
            Object urls = ReflectUtil.tryInvoke(map, "getURLPatterns")
                    .orElse(ReflectUtil.tryReadAnyOf(map, "urlPatterns").orElse(null));
            addPatternValues(patterns, urls);
        }
        return patterns;
    }

    private void addPatternValues(List<String> patterns, Object urls) {
        if (urls instanceof String[]) {
            patterns.addAll(Arrays.asList((String[]) urls));
        } else if (urls instanceof Object[]) {
            for (Object url : (Object[]) urls) {
                if (url != null) patterns.add(String.valueOf(url));
            }
        } else if (urls instanceof Collection) {
            for (Object url : (Collection<?>) urls) {
                if (url != null) patterns.add(String.valueOf(url));
            }
        }
    }

    private List<String> collectDispatcherTypes(String filterName, Object[] filterMaps) {
        List<String> types = new ArrayList<>();
        for (Object map : filterMaps) {
            if (map == null) continue;
            Object name = ReflectUtil.tryReadField(map, "filterName").orElse(null);
            if (!filterName.equals(name)) continue;
            Object d = ReflectUtil.tryReadField(map, "dispatcherTypes").orElse(null);
            if (d != null) types.add(d.toString());
        }
        return types;
    }

    private Object extractFilterInstance(Map<?, ?> filterConfigs, String filterName) {
        if (filterConfigs == null) return null;
        for (Map.Entry<?, ?> e : filterConfigs.entrySet()) {
            if (!filterName.equals(e.getKey())) continue;
            Object cfg = e.getValue();
            Object filter = ReflectUtil.tryReadField(cfg, "filter").orElse(null);
            if (filter != null) return filter;
        }
        return null;
    }

    private String codeSourceOf(Class<?> clazz) {
        try {
            ProtectionDomain pd = clazz.getProtectionDomain();
            if (pd == null) return null;
            CodeSource cs = pd.getCodeSource();
            if (cs == null || cs.getLocation() == null) return null;
            return cs.getLocation().toString();
        } catch (Throwable t) {
            return null;
        }
    }

    private String clName(ClassLoader cl) {
        return cl == null ? "bootstrap" : cl.getClass().getName();
    }
}
