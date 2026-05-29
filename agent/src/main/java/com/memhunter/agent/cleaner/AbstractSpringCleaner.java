package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.Finding;

import java.lang.reflect.Method;
import java.util.Map;

/**
 * Spring-specific cleaner base. Holds the ApplicationContext reference and
 * provides reflective Spring helpers shared by Mapping/Interceptor cleaners.
 * All Phase A/D/E orchestration lives in AbstractCleaner.
 */
public abstract class AbstractSpringCleaner extends AbstractCleaner {

    protected final Object applicationContext;

    protected AbstractSpringCleaner(Object applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    protected String contextPathOf(Finding finding) {
        return "";
    }

    /** Reflectively load a class via the ApplicationContext's classloader. */
    protected Class<?> loadClass(String name) {
        try {
            return Class.forName(name, false, applicationContext.getClass().getClassLoader());
        } catch (Throwable t) {
            return null;
        }
    }

    /** Reflectively call ApplicationContext.getBeansOfType(type). Null on failure. */
    @SuppressWarnings("unchecked")
    protected Map<String, ?> getBeansOfType(Class<?> type) {
        try {
            Method m = applicationContext.getClass().getMethod("getBeansOfType", Class.class);
            return (Map<String, ?>) m.invoke(applicationContext, type);
        } catch (Throwable t) {
            return null;
        }
    }
}
