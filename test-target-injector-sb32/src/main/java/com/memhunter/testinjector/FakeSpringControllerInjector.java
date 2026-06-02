package com.memhunter.testinjector;

import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.reflect.Method;

public class FakeSpringControllerInjector {

    private final ConfigurableApplicationContext appContext;

    public FakeSpringControllerInjector(ConfigurableApplicationContext appContext) {
        this.appContext = appContext;
    }

    public void inject() {
        DefaultListableBeanFactory factory =
                (DefaultListableBeanFactory) appContext.getBeanFactory();
        String beanName = "fakeSpringController";
        if (!factory.containsBeanDefinition(beanName)) {
            factory.registerBeanDefinition(beanName,
                    new RootBeanDefinition(FakeSpringController.class));
        }
        Object bean = appContext.getBean(beanName);
        RequestMappingHandlerMapping mapping =
                appContext.getBean(RequestMappingHandlerMapping.class);
        try {
            Method method = FakeSpringController.class.getDeclaredMethod("fake");
            Method register = RequestMappingHandlerMapping.class.getDeclaredMethod(
                    "registerHandlerMethod", Object.class, Method.class,
                    Class.forName("org.springframework.web.servlet.mvc.method.RequestMappingInfo"));
            register.setAccessible(true);
            Method getMappingForMethod = findDeclaredMethodInHierarchy(
                    mapping.getClass(), "getMappingForMethod", Method.class, Class.class);
            getMappingForMethod.setAccessible(true);
            Object info = getMappingForMethod.invoke(mapping, method, FakeSpringController.class);
            register.invoke(mapping, bean, method, info);
        } catch (Throwable t) {
            throw new RuntimeException("inject spring controller failed", t);
        }
    }

    private static Method findDeclaredMethodInHierarchy(Class<?> c, String name, Class<?>... params) {
        while (c != null) {
            try {
                return c.getDeclaredMethod(name, params);
            } catch (NoSuchMethodException e) {
                c = c.getSuperclass();
            }
        }
        throw new RuntimeException("method not found: " + name);
    }

    // Intentionally NOT annotated with @RestController to prevent Spring component-scan from
    // auto-registering it at startup. We register it manually via runtime injection — this is
    // what real memshells do (skip the annotation processor entirely).
    public static class FakeSpringController {
        @GetMapping("/spring-fake")
        public String fake() { return "fake spring response"; }
    }
}
