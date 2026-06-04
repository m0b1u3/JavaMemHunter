package com.memhunter.agent.model;

import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;
import com.memhunter.agent.scoring.bytecode.ClassBytecodeReader;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-scan context passed to every ScoringRule. Carries:
 * - The resolved Spring ApplicationContext (may be null)
 * - The Whitelist
 * - The --explain flag
 * - The BaselineIndex (empty if no --baseline provided)
 * - A lazy bytecode cache populated on demand by bytecode-* rules
 */
public class ScanContext {

    public final Object applicationContext;
    public final Whitelist whitelist;
    public final boolean explain;
    public final BaselineIndex baselineIndex;

    /**
     * Webapp class loaders gathered from the located Tomcat contexts. In a real Tomcat the agent /
     * system loader cannot see webapp classes, so bytecode reads for webapp components fail unless
     * we consult these loaders. Empty in Spring-only or test scenarios.
     */
    private final List<ClassLoader> webappLoaders;

    private final Map<String, BytecodeAnalysis> bytecodeCache = new ConcurrentHashMap<>();
    private static final BytecodeAnalysis MISS =
            new BytecodeAnalysis(Collections.<String>emptySet());

    public ScanContext(Object applicationContext, Whitelist whitelist, boolean explain,
                       BaselineIndex baselineIndex, List<ClassLoader> webappLoaders) {
        this.applicationContext = applicationContext;
        this.whitelist = whitelist;
        this.explain = explain;
        this.baselineIndex = baselineIndex != null ? baselineIndex : BaselineIndex.empty();
        this.webappLoaders = webappLoaders != null
                ? webappLoaders : Collections.<ClassLoader>emptyList();
    }

    public ScanContext(Object applicationContext, Whitelist whitelist, boolean explain,
                       BaselineIndex baselineIndex) {
        this(applicationContext, whitelist, explain, baselineIndex,
                Collections.<ClassLoader>emptyList());
    }

    /** @deprecated Use 4-arg constructor with explicit baselineIndex. */
    @Deprecated
    public ScanContext(Object applicationContext, Whitelist whitelist, boolean explain) {
        this(applicationContext, whitelist, explain, BaselineIndex.empty());
    }

    public BytecodeAnalysis bytecodeOf(String className) {
        if (className == null) return null;
        BytecodeAnalysis cached = bytecodeCache.get(className);
        if (cached != null) return cached == MISS ? null : cached;

        BytecodeAnalysis result = ClassBytecodeReader.readAndAnalyze(className, resolveClassLoader());
        // Tomcat: webapp classes are invisible to the agent/system loader; fall back to the
        // webapp loaders gathered from the located contexts.
        if (result == null) {
            for (ClassLoader wl : webappLoaders) {
                if (wl == null) continue;
                result = ClassBytecodeReader.readAndAnalyze(className, wl);
                if (result != null) break;
            }
        }
        bytecodeCache.put(className, result == null ? MISS : result);
        return result;
    }

    public void putBytecodeForTest(String className, BytecodeAnalysis analysis) {
        if (className == null) return;
        bytecodeCache.put(className, analysis == null ? MISS : analysis);
    }

    private ClassLoader resolveClassLoader() {
        if (applicationContext != null) return applicationContext.getClass().getClassLoader();
        ClassLoader tccl = Thread.currentThread().getContextClassLoader();
        return tccl != null ? tccl : ClassLoader.getSystemClassLoader();
    }
}
