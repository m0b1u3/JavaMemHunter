package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * 对比关键 Tomcat/Servlet 类的内存字节码与磁盘字节码（从 classloader 的 JAR 读）。
 * 不一致说明类在加载后被 retransform 过 —— agent 型内存马注入的标志。
 */
public class BytecodeTamperScanner {

    private static final String TYPE = "agent-bytecode-tampered";

    private static final String[] TARGET_CLASSES = {
        "org.apache.catalina.core.ApplicationFilterChain",
        "org.apache.catalina.core.StandardContextValve",
        "org.apache.catalina.connector.CoyoteAdapter",
        "javax.servlet.http.HttpServlet",
        "org.springframework.web.servlet.DispatcherServlet"
    };

    public List<Finding> scan(Object inst, ScanReport report) {
        List<Finding> findings = new ArrayList<>();
        for (String cn : TARGET_CLASSES) {
            try {
                Class<?> clazz = findLoaded(inst, cn);
                if (clazz == null) continue;

                byte[] mem = captureBytes(inst, clazz);
                byte[] disk = readFromJar(clazz);
                if (mem == null || disk == null) continue;

                if (!Arrays.equals(mem, disk)) {
                    findings.add(buildFinding(cn, mem.length, disk.length));
                }
            } catch (Throwable t) {
                report.partialErrors.add(new ScanReport.PartialError(
                    "BytecodeTamperScanner", cn + ": " + t.getMessage()));
            }
        }
        return findings;
    }

    Class<?> findLoaded(Object inst, String name) {
        Optional<Object> result = ReflectUtil.tryInvoke(inst, "getAllLoadedClasses");
        if (!result.isPresent() || !(result.get() instanceof Class<?>[])) return null;
        for (Class<?> c : (Class<?>[]) result.get()) {
            if (name.equals(c.getName())) return c;
        }
        return null;
    }

    byte[] captureBytes(Object inst, Class<?> clazz) throws Exception {
        if (!(inst instanceof Instrumentation)) return null;
        Instrumentation instrumentation = (Instrumentation) inst;
        final byte[][] captured = {null};
        ClassFileTransformer cap = new ClassFileTransformer() {
            public byte[] transform(ClassLoader l, String n, Class<?> c,
                                    ProtectionDomain pd, byte[] bytes) {
                if (c == clazz) captured[0] = bytes;
                return null;
            }
        };
        instrumentation.addTransformer(cap, true);
        try {
            instrumentation.retransformClasses(clazz);
        } finally {
            instrumentation.removeTransformer(cap);
        }
        return captured[0];
    }

    byte[] readFromJar(Class<?> clazz) throws Exception {
        String path = clazz.getName().replace('.', '/') + ".class";
        ClassLoader cl = clazz.getClassLoader();
        InputStream is = cl != null
            ? cl.getResourceAsStream(path)
            : ClassLoader.getSystemResourceAsStream(path);
        if (is == null) return null;
        try (InputStream in = is) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = in.read(tmp)) != -1) buf.write(tmp, 0, n);
            return buf.toByteArray();
        }
    }

    private Finding buildFinding(String cn, int memSize, int diskSize) {
        Finding f = new Finding();
        f.type = TYPE;
        f.name = cn;
        f.className = cn;
        f.score = 15;
        f.level = "critical";
        f.attributes.put("tamperedClass", cn);
        f.attributes.put("memSize", memSize);
        f.attributes.put("diskSize", diskSize);
        f.id = FindingIdGenerator.generate(TYPE, cn, "");
        f.reasons.add("bytecode-differs-from-jar (+15)");
        return f;
    }
}
