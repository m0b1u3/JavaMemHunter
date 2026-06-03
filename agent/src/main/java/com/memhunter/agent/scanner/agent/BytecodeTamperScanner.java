package com.memhunter.agent.scanner.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.util.FindingIdGenerator;
import com.memhunter.agent.util.ReflectUtil;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Compares the in-memory bytecode of key Tomcat/Servlet classes against their on-disk JAR
 * bytecode. A mismatch in any method body means the class was retransformed after load —
 * the hallmark of an agent-type memshell.
 *
 * <p>Comparison is done at the method-body level via ASM, NOT byte-for-byte. The raw class
 * bytes of a loaded class differ from the JAR bytes for benign reasons (constant-pool
 * reordering, debug/line-number tables, attribute ordering) even when no tampering occurred.
 * We extract a per-method opcode fingerprint (ignoring debug info and frames) and only report
 * when a method is added, removed, or its instruction sequence changes.</p>
 */
public class BytecodeTamperScanner {

    private static final String TYPE = "agent-bytecode-tampered";

    private static final String[] TARGET_CLASSES = {
        "org.apache.catalina.core.ApplicationFilterChain",
        "org.apache.catalina.core.StandardContextValve",
        "org.apache.catalina.connector.CoyoteAdapter",
        // Servlet base classes are Behinder's primary redefine targets (service()/execute()
        // method bodies get a shellcode prologue). Cover both javax and jakarta namespaces,
        // plus WebLogic's ServletStubImpl which Behinder explicitly probes for.
        "javax.servlet.http.HttpServlet",
        "jakarta.servlet.http.HttpServlet",
        "weblogic.servlet.internal.ServletStubImpl",
        "org.springframework.web.servlet.DispatcherServlet"
    };

    public List<Finding> scan(Object inst, ScanReport report, String evidenceDir) {
        List<Finding> findings = new ArrayList<>();
        for (String cn : TARGET_CLASSES) {
            try {
                Class<?> clazz = findLoaded(inst, cn);
                if (clazz == null) continue;

                byte[] mem = captureBytes(inst, clazz);
                byte[] disk = readFromJar(clazz);
                if (mem == null || disk == null) continue;

                Map<String, String> memFp = methodFingerprints(mem);
                Map<String, String> diskFp = methodFingerprints(disk);
                List<String> diffs = new ArrayList<>();
                for (String k : memFp.keySet()) {
                    if (!diskFp.containsKey(k)) {
                        diffs.add("added:" + k);
                    } else if (!memFp.get(k).equals(diskFp.get(k))) {
                        diffs.add("modified:" + k);
                    }
                }
                for (String k : diskFp.keySet()) {
                    if (!memFp.containsKey(k)) diffs.add("removed:" + k);
                }

                if (!diffs.isEmpty()) {
                    Finding f = buildFinding(cn, mem.length, disk.length);
                    f.attributes.put("tamperedMethods", diffs);

                    // v0.11: extract attacker-injected string constants (path, decrypt class, etc.)
                    java.util.Set<String> memC = ConstantPoolExtractor.utf8Constants(mem);
                    java.util.Set<String> diskC = ConstantPoolExtractor.utf8Constants(disk);
                    memC.removeAll(diskC);
                    List<String> raw = new ArrayList<>(memC);
                    f.attributes.put("injectedStringsRaw", raw);
                    f.attributes.put("injectedStrings", filterSuspicious(memC));

                    dumpEvidence(f.id, mem, disk, evidenceDir, f);
                    findings.add(f);
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

    /** Keep strings that look like injected indicators (path, long token, high entropy); drop bytecode descriptors. */
    List<String> filterSuspicious(java.util.Set<String> news) {
        List<String> out = new ArrayList<>();
        for (String s : news) {
            if (s == null || s.isEmpty()) continue;
            // 方法描述符 (...)... 和数组描述符 [... 是纯结构噪音，直接丢
            char c0 = s.charAt(0);
            if (c0 == '(' || c0 == '[') continue;
            // 对象类型描述符 Lxxx/yyy/Zzz; —— 剥出内部类名再判断（可能是注入的解密类名）
            String candidate = s;
            if (c0 == 'L' && s.endsWith(";") && s.length() > 2) {
                candidate = s.substring(1, s.length() - 1);  // javax/crypto/Cipher
            }
            boolean looksPath = candidate.indexOf('/') >= 0 || candidate.indexOf('*') >= 0;
            if (!looksPath && candidate.length() <= 4) continue;
            boolean highEntropy = shannonEntropy(candidate) > 3.5;
            boolean longToken = candidate.length() > 8;
            if (looksPath || highEntropy || longToken) out.add(candidate);
        }
        return out;
    }

    private double shannonEntropy(String s) {
        int[] freq = new int[256];
        int counted = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch < 256) { freq[ch]++; counted++; }
        }
        if (counted == 0) return 0.0;
        double ent = 0.0;
        for (int fr : freq) {
            if (fr > 0) {
                double p = (double) fr / counted;
                ent -= p * (Math.log(p) / Math.log(2));
            }
        }
        return ent;
    }

    void dumpEvidence(String findingId, byte[] mem, byte[] disk, String evidenceDir, Finding f) {
        if (evidenceDir == null || evidenceDir.isEmpty()) {
            f.attributes.put("evidenceDumped", false);
            return;
        }
        try {
            java.nio.file.Path dir = java.nio.file.Paths.get(evidenceDir, "evidence", findingId);
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.write(dir.resolve("tampered.class"), mem);
            java.nio.file.Files.write(dir.resolve("original.class"), disk);
            f.attributes.put("evidenceDumped", true);
        } catch (Throwable t) {
            f.attributes.put("evidenceDumped", false);
        }
    }

    /**
     * Build a map of methodName+descriptor -> SHA-256 of the method's opcode sequence.
     * Debug info and stack-map frames are skipped so benign re-compilation/reordering does
     * not register as a difference; only real instruction changes do.
     */
    Map<String, String> methodFingerprints(byte[] classBytes) {
        final Map<String, String> result = new HashMap<>();
        ClassReader cr = new ClassReader(classBytes);
        cr.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                final String key = name + descriptor;
                final StringBuilder ops = new StringBuilder();
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override public void visitInsn(int opcode) { ops.append(opcode).append(';'); }
                    @Override public void visitIntInsn(int opcode, int operand) { ops.append(opcode).append(';'); }
                    @Override public void visitVarInsn(int opcode, int var) { ops.append(opcode).append(';'); }
                    @Override public void visitTypeInsn(int opcode, String type) { ops.append(opcode).append(':').append(type).append(';'); }
                    @Override public void visitFieldInsn(int opcode, String owner, String n, String d) { ops.append(opcode).append(':').append(owner).append('.').append(n).append(';'); }
                    @Override public void visitMethodInsn(int opcode, String owner, String n, String d, boolean itf) { ops.append(opcode).append(':').append(owner).append('.').append(n).append(';'); }
                    @Override public void visitLdcInsn(Object value) { ops.append("LDC:").append(value).append(';'); }
                    @Override public void visitJumpInsn(int opcode, Label label) { ops.append(opcode).append(';'); }
                    @Override public void visitEnd() { result.put(key, sha256(ops.toString())); }
                };
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return result;
    }

    private String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(s.hashCode());
        }
    }
}
