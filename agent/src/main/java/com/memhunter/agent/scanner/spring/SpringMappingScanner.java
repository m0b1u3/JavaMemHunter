package com.memhunter.agent.scanner.spring;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.lang.reflect.Method;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class SpringMappingScanner {

    private static final String TYPE = "spring-mapping";
    private static final String HANDLER_MAPPING_CLASS =
            "org.springframework.web.servlet.handler.AbstractHandlerMethodMapping";

    private final Object applicationContext;

    public SpringMappingScanner(Object applicationContext) {
        this.applicationContext = applicationContext;
    }

    public List<Finding> scan(ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        try {
            Class<?> mappingClass = loadClass(HANDLER_MAPPING_CLASS);
            if (mappingClass == null) {
                report.partialErrors.add(new ScanReport.PartialError(
                        "SpringMappingScanner", "AbstractHandlerMethodMapping not loadable"));
                return findings;
            }
            Map<String, ?> beans = getBeansOfType(applicationContext, mappingClass, report);
            if (beans == null) return findings;
            for (Map.Entry<String, ?> e : beans.entrySet()) {
                Object mapping = e.getValue();
                Optional<Object> handlers = ReflectUtil.tryInvoke(mapping, "getHandlerMethods");
                if (!handlers.isPresent() || !(handlers.get() instanceof Map)) continue;
                Map<?, ?> handlerMap = (Map<?, ?>) handlers.get();
                for (Map.Entry<?, ?> h : handlerMap.entrySet()) {
                    Finding f = buildFinding(h.getKey(), h.getValue(), e.getKey());
                    if (f != null) findings.add(f);
                }
            }
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                    "SpringMappingScanner", "exception: " + t.getMessage()));
        }
        return findings;
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
                    "SpringMappingScanner", "getBeansOfType failed: " + t.getMessage()));
            return null;
        }
    }

    private Finding buildFinding(Object info, Object handlerMethod, String mappingBeanName) {
        if (handlerMethod == null) return null;
        Finding f = new Finding();
        f.type = TYPE;
        Class<?> beanType = (Class<?>) ReflectUtil.tryInvoke(handlerMethod, "getBeanType").orElse(null);
        f.className = beanType == null ? "" : beanType.getName();
        Object method = ReflectUtil.tryInvoke(handlerMethod, "getMethod").orElse(null);
        String methodName = method == null ? "" : String.valueOf(method);
        f.name = mappingBeanName + "#" + (method == null ? "" : ((Method) method).getName());
        f.attributes.put("handlerMethod", methodName);
        f.attributes.put("beanName", mappingBeanName);
        f.attributes.put("pattern", String.valueOf(info));
        if (beanType != null) {
            f.codeSource = codeSourceOf(beanType);
            f.classLoader = clName(beanType.getClassLoader());
        }
        f.reasons.add("registered in Spring HandlerMapping");
        f.level = "low";
        f.score = 3;
        f.recommendation = "review whether mapping is registered through legitimate source";
        f.id = FindingIdGenerator.generate(TYPE, f.className, String.valueOf(info));
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
