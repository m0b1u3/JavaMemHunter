package com.memhunter.agent.scanner.runtime;

import com.memhunter.agent.model.Finding;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Map;

public class RuntimeOnlyDetector {

    private static final String[] WEB_ANNOTATIONS = new String[] {
            "javax.servlet.annotation.WebFilter",
            "javax.servlet.annotation.WebServlet",
            "javax.servlet.annotation.WebListener",
            "jakarta.servlet.annotation.WebFilter",
            "jakarta.servlet.annotation.WebServlet",
            "jakarta.servlet.annotation.WebListener"
    };

    private final Object applicationContext;

    public RuntimeOnlyDetector(Object applicationContext) {
        this.applicationContext = applicationContext;
    }

    public void evaluate(Finding finding) {
        if (finding == null || finding.className == null) return;
        if (hasWebAnnotation(finding.className)) return;
        if (isSpringManaged(finding.className)) return;
        finding.reasons.add("runtime-only");
        if ("low".equals(finding.level)) {
            finding.level = "suspicious";
            finding.score = finding.score + 3;
        }
    }

    private boolean hasWebAnnotation(String className) {
        try {
            Class<?> c = Class.forName(className);
            for (String annName : WEB_ANNOTATIONS) {
                try {
                    @SuppressWarnings("unchecked")
                    Class<? extends Annotation> annClass =
                            (Class<? extends Annotation>) Class.forName(annName, false, c.getClassLoader());
                    if (c.isAnnotationPresent(annClass)) return true;
                } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private boolean isSpringManaged(String className) {
        if (applicationContext == null) return false;
        try {
            Class<?> c = Class.forName(className);
            Method m = applicationContext.getClass().getMethod("getBeansOfType", Class.class);
            Object beans = m.invoke(applicationContext, c);
            if (beans instanceof Map) {
                return !((Map<?, ?>) beans).isEmpty();
            }
        } catch (Throwable ignored) {}
        return false;
    }
}
