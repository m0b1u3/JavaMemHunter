package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Scans registered {@link java.lang.instrument.ClassFileTransformer} instances.
 * A healthy Tomcat/Spring Boot has no non-framework Transformers.
 * Behinder AgentNoFile registers one after injection.
 */
public class TransformerScanner {

    private static final String TYPE = "agent-transformer";

    private static final String[] SAFE_PREFIXES = {
        "org.apache.skywalking.",
        "com.taobao.arthas.",
        "com.navercorp.pinpoint.",
        "net.bytebuddy.",
        "org.jacoco.",
        "co.elastic.apm.",
        "com.newrelic.",
        "com.dynatrace.",
        "io.opentelemetry."
    };

    /** Self-exemption: TransformerScanner (and any subclass) is never suspicious. */
    private static final String SELF_CLASS = TransformerScanner.class.getName();

    public List<Finding> scan(Object inst, ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        try {
            Optional<Object> tmOpt = ReflectUtil.tryReadField(inst, "mTransformerManager");
            if (!tmOpt.isPresent()) {
                report.partialErrors.add(new ScanReport.PartialError(
                    "TransformerScanner",
                    "mTransformerManager field not accessible on " + inst.getClass().getName()));
                return findings;
            }
            Object tm = tmOpt.get();
            Optional<Object> trsOpt = ReflectUtil.tryReadField(tm, "mTransformers");
            if (!trsOpt.isPresent() || !(trsOpt.get() instanceof Object[])) return findings;

            Object[] transformers = (Object[]) trsOpt.get();
            for (Object tr : transformers) {
                if (tr == null) continue;
                String cn = tr.getClass().getName();
                if (isKnownSafe(cn)) continue;

                Finding f = new Finding();
                f.type = TYPE;
                f.name = cn;
                f.className = cn;
                f.score = 10;
                f.level = "high";
                f.classLoader = tr.getClass().getClassLoader() != null
                    ? tr.getClass().getClassLoader().getClass().getName() : "bootstrap";
                f.attributes.put("transformerClass", cn);
                f.id = FindingIdGenerator.generate(TYPE, cn, "");
                f.reasons.add("non-whitelist-transformer (+10)");
                findings.add(f);
            }
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                "TransformerScanner", "exception: " + t.getMessage()));
        }
        return findings;
    }

    private boolean isKnownSafe(String className) {
        if (className.equals(SELF_CLASS)) return true;
        for (String prefix : SAFE_PREFIXES) {
            if (className.startsWith(prefix)) return true;
        }
        return false;
    }
}
