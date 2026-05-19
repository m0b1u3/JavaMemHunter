package com.memhunter.agent.scanner.spring;

import com.memhunter.agent.util.ReflectUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class ServletContextAttrProvider implements ApplicationContextProvider {

    private static final String ROOT_ATTR =
            "org.springframework.web.context.WebApplicationContext.ROOT";

    @Override
    public String name() {
        return "ServletContextAttrProvider";
    }

    @Override
    public List<Object> findAll(List<Object> tomcatContexts, List<Object> tomcatServletInstances) {
        List<Object> results = new ArrayList<>();
        Set<Object> seen = new HashSet<>();
        for (Object ctx : tomcatContexts) {
            try {
                Optional<Object> sc = ReflectUtil.tryInvoke(ctx, "getServletContext");
                if (!sc.isPresent()) continue;
                Object root = invokeStringArg(sc.get(), "getAttribute", ROOT_ATTR);
                if (root != null && seen.add(root)) results.add(root);
            } catch (Throwable ignored) {}
        }
        return results;
    }

    private Object invokeStringArg(Object target, String method, String arg) {
        try {
            java.lang.reflect.Method m = target.getClass().getMethod(method, String.class);
            return m.invoke(target, arg);
        } catch (Throwable t) {
            return null;
        }
    }
}
