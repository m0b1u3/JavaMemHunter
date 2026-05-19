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

public class TomcatValveScanner {

    private static final String TYPE = "tomcat-valve";
    private final Object context;

    public TomcatValveScanner(Object context) {
        this.context = context;
    }

    public List<Finding> scan(ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        try {
            String contextPath = ReflectUtil.tryInvoke(context, "getPath")
                    .map(String::valueOf).orElse("");
            Optional<Object> pipeline = ReflectUtil.tryInvoke(context, "getPipeline");
            if (!pipeline.isPresent()) {
                report.partialErrors.add(new ScanReport.PartialError(
                        "TomcatValveScanner", "no pipeline on " + contextPath));
                return findings;
            }
            Object valve = ReflectUtil.tryInvoke(pipeline.get(), "getFirst").orElse(null);
            int idx = 0;
            Set<Object> visited = new HashSet<>();
            while (valve != null && visited.add(valve)) {
                findings.add(buildFinding(valve, contextPath, idx));
                valve = ReflectUtil.tryInvoke(valve, "getNext").orElse(null);
                idx++;
                if (idx > 100) break; // hard stop, defensive
            }
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                    "TomcatValveScanner", "exception: " + t.getMessage()));
        }
        return findings;
    }

    private Finding buildFinding(Object valve, String contextPath, int idx) {
        Finding f = new Finding();
        Class<?> clazz = valve.getClass();
        f.type = TYPE;
        f.name = clazz.getSimpleName();
        f.className = clazz.getName();
        f.codeSource = codeSourceOf(clazz);
        f.classLoader = clName(clazz.getClassLoader());
        f.attributes.put("containerLevel", "Context");
        f.attributes.put("pipelineIndex", idx);
        f.attributes.put("contextPath", contextPath);
        f.reasons.add("registered as Valve in Tomcat pipeline");
        f.level = "low";
        f.score = 3;
        f.recommendation = "review whether Valve source is legitimate";
        f.id = FindingIdGenerator.generate(TYPE, f.className, contextPath + "#" + idx);
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
