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
                if (!isSuspicious(c, report)) continue;
                findings.add(buildFinding(c));
            }
        } catch (Throwable t) {
            report.partialErrors.add(new ScanReport.PartialError(
                "DynamicClassScanner", "exception: " + t.getMessage()));
        }
        return findings;
    }

    /**
     * Variant without a report — delegates to the full overload with a throwaway report.
     * Kept for callers that do not have a {@link ScanReport} (e.g. unit tests that pre-date
     * the observable-signal requirement).
     */
    boolean isSuspicious(Class<?> c) {
        return isSuspicious(c, new ScanReport());
    }

    boolean isSuspicious(Class<?> c, ScanReport report) {
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
            // readAndAnalyze 内部已 catch(Throwable) 返回 null，无需外层 try/catch
            BytecodeAnalysis a = ClassBytecodeReader.readAndAnalyze(name, c.getClassLoader());
            if (a == null) {
                // 字节码不可读：保持 v0.12 降误报权衡（不升级为 finding），但留可观测信号供人工复核
                report.partialErrors.add(new ScanReport.PartialError(
                    "DynamicClassScanner",
                    "bytecode unreadable for suspicious dynamic class (no codeSource + unusual loader): "
                        + name + " — skipped to reduce false positives; manual review recommended"));
                return false;
            }
            // 字节码可读但不含 4 个高确信度恶意锚点（Runtime.exec/ProcessBuilder.start/
            // defineClass/Cipher.doFinal）时，此处静默返回 false——这是 v0.12「降误报优先」的
            // 已知权衡：可读但无特征的动态类不再上报，也不发 partialError（与「不可读」分支不同）。
            // 补充检测渠道：agent 型 redefine 马走 BytecodeTamperScanner；自定义 transformer 走
            // TransformerScanner；这些路径不依赖本方法的恶意锚点判定。详见设计文档 §25 v0.12 已知局限。
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
