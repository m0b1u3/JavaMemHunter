package com.memhunter.agent.scanner;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.util.FindingIdGenerator;

import java.lang.instrument.Instrumentation;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;

public class ClassScanner {

    private final Instrumentation inst;

    public ClassScanner(Instrumentation inst) {
        this.inst = inst;
    }

    public List<Finding> scan() {
        List<Finding> findings = new ArrayList<>();
        Class<?>[] allClasses = inst.getAllLoadedClasses();
        for (Class<?> clazz : allClasses) {
            String type = WebComponentDetector.classify(clazz);
            if (type == null) continue;

            Finding f = new Finding();
            f.type = "class-" + type.toLowerCase();
            f.name = clazz.getSimpleName();
            f.className = clazz.getName();
            f.codeSource = codeSourceOf(clazz);
            f.classLoader = clazz.getClassLoader() == null
                    ? "bootstrap"
                    : clazz.getClassLoader().getClass().getName();
            f.id = FindingIdGenerator.generate(f.type, f.className, "");
            findings.add(f);
        }
        return findings;
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
}
