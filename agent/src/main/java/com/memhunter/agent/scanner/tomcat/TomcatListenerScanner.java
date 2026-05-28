package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class TomcatListenerScanner {

    private final Object context;

    public TomcatListenerScanner(Object context) {
        this.context = context;
    }

    public List<Finding> scan(ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        try {
            String contextPath = ReflectUtil.tryInvoke(context, "getPath")
                    .map(String::valueOf).orElse("");
            Set<Object> seen = new HashSet<>();
            collectFrom(eventListeners(), contextPath, findings, seen);
            collectFrom(lifecycleListeners(), contextPath, findings, seen);
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                    "TomcatListenerScanner", "exception: " + t.getMessage()));
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

    private void collectFrom(Object[] listeners, String contextPath, List<Finding> out,
                             Set<Object> seen) {
        if (listeners == null) return;
        for (Object listener : listeners) {
            if (listener == null || !seen.add(listener)) continue;
            out.add(buildFinding(listener, contextPath));
        }
    }

    private Object[] eventListeners() {
        Optional<Object> viaGetter = ReflectUtil.tryInvoke(context, "getApplicationEventListeners");
        if (viaGetter.isPresent()) return toArray(viaGetter.get());
        return toArray(ReflectUtil.tryReadAnyOf(context,
            "applicationEventListeners",
            "applicationEventListenersList").orElse(null));
    }

    private Object[] lifecycleListeners() {
        Optional<Object> viaGetter = ReflectUtil.tryInvoke(context, "getApplicationLifecycleListeners");
        if (viaGetter.isPresent()) return toArray(viaGetter.get());
        return toArray(ReflectUtil.tryReadAnyOf(context,
            "applicationLifecycleListeners",
            "applicationLifecycleListenersObjects").orElse(null));
    }

    private Object[] toArray(Object value) {
        if (value instanceof Object[]) return (Object[]) value;
        if (value instanceof List) return ((List<?>) value).toArray();
        return null;
    }

    private Finding buildFinding(Object listener, String contextPath) {
        Finding f = new Finding();
        Class<?> clazz = listener.getClass();
        f.type = "tomcat-listener-" + classifyKind(clazz);
        f.name = clazz.getSimpleName();
        f.className = clazz.getName();
        f.codeSource = codeSourceOf(clazz);
        f.classLoader = clName(clazz.getClassLoader());
        f.attributes.put("listenerKind", classifyKind(clazz));
        f.attributes.put("contextPath", contextPath);
        f.id = FindingIdGenerator.generate(f.type, f.className, "");
        return f;
    }

    private String classifyKind(Class<?> clazz) {
        if (implementsAny(clazz,
                "javax.servlet.ServletRequestListener",
                "jakarta.servlet.ServletRequestListener")) return "request";
        if (implementsAny(clazz,
                "javax.servlet.http.HttpSessionListener",
                "jakarta.servlet.http.HttpSessionListener")) return "session";
        if (implementsAny(clazz,
                "javax.servlet.ServletContextListener",
                "jakarta.servlet.ServletContextListener")) return "context";
        return "other";
    }

    private boolean implementsAny(Class<?> clazz, String... ifaceNames) {
        java.util.Deque<Class<?>> q = new java.util.ArrayDeque<>();
        Set<Class<?>> visited = new HashSet<>();
        q.add(clazz);
        while (!q.isEmpty()) {
            Class<?> c = q.poll();
            if (c == null || !visited.add(c)) continue;
            for (String name : ifaceNames) {
                if (c.getName().equals(name)) return true;
            }
            for (Class<?> i : c.getInterfaces()) q.add(i);
            if (c.getSuperclass() != null) q.add(c.getSuperclass());
        }
        return false;
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
