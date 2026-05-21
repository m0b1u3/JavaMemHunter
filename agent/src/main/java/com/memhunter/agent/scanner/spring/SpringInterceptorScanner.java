package com.memhunter.agent.scanner.spring;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.lang.reflect.Method;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class SpringInterceptorScanner {

    private static final String TYPE = "spring-interceptor";
    private static final String HANDLER_MAPPING_CLASS =
            "org.springframework.web.servlet.handler.AbstractHandlerMapping";

    private final Object applicationContext;

    public SpringInterceptorScanner(Object applicationContext) {
        this.applicationContext = applicationContext;
    }

    public List<Finding> scan(ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        Set<Object> seen = new HashSet<>();
        try {
            Class<?> mappingClass = loadClass(HANDLER_MAPPING_CLASS);
            if (mappingClass == null) {
                report.partialErrors.add(new ScanReport.PartialError(
                        "SpringInterceptorScanner", "AbstractHandlerMapping not loadable"));
                return findings;
            }
            Map<String, ?> beans = getBeansOfType(applicationContext, mappingClass, report);
            if (beans == null) return findings;
            for (Object mapping : beans.values()) {
                Optional<Object> adapted = ReflectUtil.tryReadField(mapping, "adaptedInterceptors");
                if (!adapted.isPresent() || !(adapted.get() instanceof Collection)) continue;
                Collection<?> interceptors = (Collection<?>) adapted.get();
                int order = 0;
                for (Object interceptor : interceptors) {
                    if (interceptor == null || !seen.add(interceptor)) continue;
                    findings.add(buildFinding(interceptor, order));
                    order++;
                }
            }
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                    "SpringInterceptorScanner", "exception: " + t.getMessage()));
        }
        return dedupById(findings);
    }

    private List<Finding> dedupById(List<Finding> findings) {
        List<Finding> result = new ArrayList<>();
        Set<String> seenIds = new HashSet<>();
        for (Finding f : findings) {
            if (f.id != null && seenIds.add(f.id)) {
                result.add(f);
            }
        }
        return result;
    }

    private Class<?> loadClass(String name) {
        try {
            return Class.forName(name, false, applicationContext.getClass().getClassLoader());
        } catch (Throwable t) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, ?> getBeansOfType(Object appCtx, Class<?> type, ScanReport report) {
        try {
            Method m = appCtx.getClass().getMethod("getBeansOfType", Class.class);
            return (Map<String, ?>) m.invoke(appCtx, type);
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                    "SpringInterceptorScanner", "getBeansOfType failed: " + t.getMessage()));
            return null;
        }
    }

    private Finding buildFinding(Object interceptor, int order) {
        Finding f = new Finding();
        Class<?> clazz = interceptor.getClass();
        f.type = TYPE;
        f.name = clazz.getSimpleName();
        f.className = clazz.getName();
        f.codeSource = codeSourceOf(clazz);
        f.classLoader = clName(clazz.getClassLoader());
        f.attributes.put("order", order);
        Optional<Object> include = ReflectUtil.tryReadField(interceptor, "includePatterns");
        include.ifPresent(v -> f.attributes.put("includePatterns", v));
        Optional<Object> exclude = ReflectUtil.tryReadField(interceptor, "excludePatterns");
        exclude.ifPresent(v -> f.attributes.put("excludePatterns", v));

        f.id = FindingIdGenerator.generate(TYPE, f.className, "");
        return f;
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
