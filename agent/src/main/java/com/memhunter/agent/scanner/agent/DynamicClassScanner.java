package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.scoring.BytecodeMaliceCheck;
import com.memhunter.agent.scoring.JvmGeneratedClasses;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import com.memhunter.agent.scoring.bytecode.ClassBytecodeReader;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 扫描所有已加载类，找出无 CodeSource 且由非标准 ClassLoader 加载的类 ——
 * agent 型 / defineClass 型内存马的典型指纹。
 */
public class DynamicClassScanner {

    private static final String TYPE = "agent-dynamic-class";

    private static final Set<String> STANDARD_LOADERS = new HashSet<>(Arrays.asList(
        "org.springframework.boot.loader.LaunchedURLClassLoader",
        "org.apache.catalina.loader.ParallelWebappClassLoader",
        "org.apache.catalina.loader.WebappClassLoader",
        "org.apache.jasper.servlet.JasperLoader",
        "java.net.URLClassLoader",
        "jdk.internal.loader.ClassLoaders$AppClassLoader",
        "sun.misc.Launcher$AppClassLoader",
        "sun.misc.Launcher$ExtClassLoader"
    ));

    public List<Finding> scan(Object inst, ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        try {
            Optional<Object> result = ReflectUtil.tryInvoke(inst, "getAllLoadedClasses");
            if (!result.isPresent() || !(result.get() instanceof Class<?>[])) {
                report.partialErrors.add(new ScanReport.PartialError(
                    "DynamicClassScanner",
                    "getAllLoadedClasses not available on " + inst.getClass().getName()));
                return findings;
            }
            Class<?>[] allClasses = (Class<?>[]) result.get();
            for (Class<?> c : allClasses) {
                if (!isSuspicious(c)) continue;
                findings.add(buildFinding(c));
            }
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                "DynamicClassScanner", "exception: " + t.getMessage()));
        }
        return findings;
    }

    boolean isSuspicious(Class<?> c) {
        if (c == null || c.getClassLoader() == null) return false;  // bootstrap → 跳过
        try {
            String name = c.getName();
            // JVM 自动生成的反射/Lambda/Proxy 类直接跳过
            if (JvmGeneratedClasses.isJvmGenerated(name)) return false;

            ProtectionDomain pd = c.getProtectionDomain();
            if (pd == null) return false;
            CodeSource cs = pd.getCodeSource();
            boolean noSource = cs == null || cs.getLocation() == null;
            if (!noSource) return false;
            String loaderName = c.getClassLoader().getClass().getName();
            boolean unusualLoader = !STANDARD_LOADERS.contains(loaderName);
            boolean shortName = !name.contains(".") && name.length() <= 5;
            if (!(unusualLoader || shortName)) return false;

            // v0.12: 必须包含恶意字节码特征才上报，无特征的动态类不再报
            BytecodeAnalysis a;
            try {
                a = ClassBytecodeReader.readAndAnalyze(name, c.getClassLoader());
            } catch (Throwable t) {
                return false;
            }
            return BytecodeMaliceCheck.hasMalice(a);
        } catch (Throwable t) {
            return false;
        }
    }

    private Finding buildFinding(Class<?> c) {
        Finding f = new Finding();
        f.type = TYPE;
        f.name = c.getSimpleName().isEmpty() ? c.getName() : c.getSimpleName();
        f.className = c.getName();
        f.classLoader = c.getClassLoader().getClass().getName();
        f.attributes.put("isDynamic", Boolean.TRUE);
        f.score = 4;
        f.level = mapLevel(f.score);
        f.id = FindingIdGenerator.generate(TYPE, c.getName(), "");
        f.reasons.add("no-code-source (+2)");
        f.reasons.add("unusual-classloader (+2)");
        return f;
    }

    private String mapLevel(int score) {
        if (score >= 10) return "critical";
        if (score >= 7) return "high";
        if (score >= 4) return "suspicious";
        return "low";
    }
}
