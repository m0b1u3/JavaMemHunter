package com.memhunter.agent.scoring.bytecode;

import org.objectweb.asm.ClassReader;

import java.io.InputStream;

/**
 * Reads a class's .class bytes via the given ClassLoader and analyzes them.
 * Returns null on any failure (class not found, IO error, ASM error).
 */
public final class ClassBytecodeReader {

    private ClassBytecodeReader() {}

    public static BytecodeAnalysis readAndAnalyze(String className, ClassLoader cl) {
        if (className == null) return null;
        try {
            String resource = className.replace('.', '/') + ".class";
            ClassLoader loader = cl != null ? cl : ClassBytecodeReader.class.getClassLoader();
            try (InputStream in = loader.getResourceAsStream(resource)) {
                if (in == null) return null;
                ClassReader reader = new ClassReader(in);
                BytecodeAnalyzer analyzer = new BytecodeAnalyzer();
                reader.accept(analyzer, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                return analyzer.toAnalysis();
            }
        } catch (Throwable t) {
            return null;
        }
    }
}
