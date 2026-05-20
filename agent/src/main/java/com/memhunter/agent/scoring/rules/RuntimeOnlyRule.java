package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Map;

public class RuntimeOnlyRule implements ScoringRule {

    private static final String[] WEB_ANNOTATIONS = {
            "javax.servlet.annotation.WebFilter",
            "javax.servlet.annotation.WebServlet",
            "javax.servlet.annotation.WebListener",
            "jakarta.servlet.annotation.WebFilter",
            "jakarta.servlet.annotation.WebServlet",
            "jakarta.servlet.annotation.WebListener"
    };

    public String name() { return "runtime-only"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.className == null) return 0;
        if (!isRuntimeRegistryFinding(finding.type)) return 0;
        if (hasWebAnnotation(finding.className, ctx)) return 0;
        if (isSpringManaged(finding.className, ctx)) return 0;
        return 4;
    }

    private boolean isRuntimeRegistryFinding(String type) {
        return type != null && (type.startsWith("tomcat-") || type.startsWith("spring-"));
    }

    private boolean hasWebAnnotation(String className, ScanContext ctx) {
        try {
            Class<?> c = loadTargetClass(className, ctx);
            if (c == null) return false;
            for (String annName : WEB_ANNOTATIONS) {
                try {
                    @SuppressWarnings("unchecked")
                    Class<? extends Annotation> ann =
                            (Class<? extends Annotation>) Class.forName(annName, false, c.getClassLoader());
                    if (c.isAnnotationPresent(ann)) return true;
                } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private boolean isSpringManaged(String className, ScanContext ctx) {
        if (ctx == null || ctx.applicationContext == null) return false;
        try {
            Class<?> c = loadTargetClass(className, ctx);
            if (c == null) return false;
            Method m = ctx.applicationContext.getClass().getMethod("getBeansOfType", Class.class);
            Object beans = m.invoke(ctx.applicationContext, c);
            return beans instanceof Map && !((Map<?, ?>) beans).isEmpty();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private Class<?> loadTargetClass(String className, ScanContext ctx) {
        if (ctx != null && ctx.applicationContext != null) {
            try {
                return Class.forName(className, false, ctx.applicationContext.getClass().getClassLoader());
            } catch (Throwable ignored) {}
        }
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            if (cl != null) return Class.forName(className, false, cl);
        } catch (Throwable ignored) {}
        try {
            return Class.forName(className);
        } catch (Throwable ignored) {
            return null;
        }
    }
}
