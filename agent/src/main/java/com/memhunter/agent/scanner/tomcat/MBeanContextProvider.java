package com.memhunter.agent.scanner.tomcat;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MBeanContextProvider implements StandardContextProvider {

    @Override
    public String name() {
        return "MBeanContextProvider";
    }

    @Override
    public List<Object> findAllContexts(Instrumentation inst) {
        List<Object> contexts = new ArrayList<>();
        try {
            MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
            ObjectName query = new ObjectName("Catalina:type=Context,*");
            Set<ObjectName> names = mbs.queryNames(query, null);
            Set<Object> seen = new HashSet<>();
            for (ObjectName on : names) {
                Object ctx = resolveContext(mbs, on);
                if (ctx != null && seen.add(ctx)) {
                    contexts.add(ctx);
                }
            }
        } catch (Throwable t) {
            // swallow and return whatever was collected
        }
        return contexts;
    }

    private Object resolveContext(MBeanServer mbs, ObjectName on) {
        try {
            // Try: getAttribute("managedResource") — Tomcat exposes this
            try {
                Object mr = mbs.getAttribute(on, "managedResource");
                if (mr != null) return mr;
            } catch (Throwable ignored) {}
            // Try: getAttribute("context") — some Tomcat versions
            try {
                Object c = mbs.getAttribute(on, "context");
                if (c != null) return c;
            } catch (Throwable ignored) {}
            return null;
        } catch (Throwable t) {
            return null;
        }
    }
}
