package com.memhunter.testinjector;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.List;

public class FakeSpringInterceptorInjector {

    private final ConfigurableApplicationContext appContext;

    public FakeSpringInterceptorInjector(ConfigurableApplicationContext appContext) {
        this.appContext = appContext;
    }

    public void inject() {
        RequestMappingHandlerMapping mapping =
                appContext.getBean(RequestMappingHandlerMapping.class);
        try {
            Field f = findField(mapping.getClass(), "adaptedInterceptors");
            if (f == null) throw new RuntimeException("adaptedInterceptors field not found");
            f.setAccessible(true);
            Object value = f.get(mapping);
            if (!(value instanceof Collection)) {
                throw new RuntimeException("adaptedInterceptors not a Collection");
            }
            @SuppressWarnings("unchecked")
            List<HandlerInterceptor> list = (List<HandlerInterceptor>) value;
            list.add(new FakeInterceptor());
        } catch (Throwable t) {
            throw new RuntimeException("inject spring interceptor failed", t);
        }
    }

    private Field findField(Class<?> c, String name) {
        while (c != null) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        return null;
    }

    public static class FakeInterceptor implements HandlerInterceptor {
        @Override
        public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) {
            return true;
        }
    }
}
