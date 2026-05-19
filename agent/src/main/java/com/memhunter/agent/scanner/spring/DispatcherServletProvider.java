package com.memhunter.agent.scanner.spring;

import com.memhunter.agent.util.ReflectUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class DispatcherServletProvider implements ApplicationContextProvider {

    private static final String DISPATCHER_SERVLET =
            "org.springframework.web.servlet.DispatcherServlet";

    @Override
    public String name() {
        return "DispatcherServletProvider";
    }

    @Override
    public List<Object> findAll(List<Object> tomcatContexts, List<Object> tomcatServletInstances) {
        List<Object> results = new ArrayList<>();
        Set<Object> seen = new HashSet<>();
        for (Object servlet : tomcatServletInstances) {
            if (servlet == null) continue;
            if (!DISPATCHER_SERVLET.equals(servlet.getClass().getName())) continue;
            Optional<Object> appCtx = ReflectUtil.tryReadField(servlet, "webApplicationContext");
            if (appCtx.isPresent() && seen.add(appCtx.get())) {
                results.add(appCtx.get());
            }
        }
        return results;
    }
}
