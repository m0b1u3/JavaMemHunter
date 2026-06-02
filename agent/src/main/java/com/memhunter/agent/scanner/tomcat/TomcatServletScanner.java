package com.memhunter.agent.scanner.tomcat;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class TomcatServletScanner {

    private static final String TYPE = "tomcat-servlet";
    private final Object context;

    public TomcatServletScanner(Object context) {
        this.context = context;
    }

    public List<Finding> scan(ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        try {
            String contextPath = ReflectUtil.tryInvoke(context, "getPath")
                    .map(String::valueOf).orElse("");
            Optional<Object> children = ReflectUtil.tryInvoke(context, "findChildren");
            if (!children.isPresent() || !(children.get() instanceof Object[])) {
                report.partialErrors.add(new ScanReport.PartialError(
                        "TomcatServletScanner", "findChildren not available on " + contextPath));
                return findings;
            }
            for (Object wrapper : (Object[]) children.get()) {
                if (wrapper == null) continue;
                String wrapperClassName = wrapper.getClass().getName();
                // Accept StandardWrapper (production) or any wrapper with getServletClass (tests / embedded containers)
                boolean isStandardWrapper = wrapperClassName.endsWith("StandardWrapper");
                boolean hasServletClass = ReflectUtil.tryInvoke(wrapper, "getServletClass").isPresent();
                if (!isStandardWrapper && !hasServletClass) continue;
                findings.add(buildFinding(wrapper, contextPath));
            }
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                    "TomcatServletScanner", "exception: " + t.getMessage()));
        }
        return findings;
    }

    private Finding buildFinding(Object wrapper, String contextPath) {
        Finding f = new Finding();
        f.type = TYPE;
        f.name = ReflectUtil.tryInvoke(wrapper, "getName").map(String::valueOf).orElse(null);
        f.className = ReflectUtil.tryInvoke(wrapper, "getServletClass").map(String::valueOf).orElse(null);
        f.attributes.put("servletClass", f.className);
        f.attributes.put("contextPath", contextPath);
        Optional<Object> mappings = ReflectUtil.tryInvoke(wrapper, "findMappings");
        if (mappings.isPresent() && mappings.get() instanceof String[]) {
            f.attributes.put("mappings", Arrays.asList((String[]) mappings.get()));
        }
        Optional<Object> loadOnStartup = ReflectUtil.tryInvoke(wrapper, "getLoadOnStartup");
        loadOnStartup.ifPresent(v -> f.attributes.put("loadOnStartup", v));

        Optional<Object> instance = ReflectUtil.tryInvoke(wrapper, "getServlet");
        if (instance.isPresent() && instance.get() != null) {
            f.codeSource = codeSourceOf(instance.get().getClass());
            f.classLoader = clName(instance.get().getClass().getClassLoader());
            // v0.10: tag isDynamic — false means declared in web.xml, true means runtime injection
            boolean isDynamic = ReflectUtil.tryInvokeWithArg(context, "wasCreatedDynamicServlet", instance.get())
                    .map(v -> Boolean.TRUE.equals(v))
                    .orElse(true);  // conservative: if API absent, assume dynamic (don't suppress scoring)
            f.attributes.put("isDynamic", isDynamic);
        }

        f.id = FindingIdGenerator.generate(TYPE, f.className == null ? "" : f.className,
                f.name == null ? "" : f.name);
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
