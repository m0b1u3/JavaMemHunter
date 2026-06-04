package com.memhunter.agent.scoring;

import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.bytecode.BytecodeAnalysis;

/**
 * Shared high-confidence malice check on class bytecode.
 *
 * <p>Only flags a small set of API calls with very low false-positive rate:
 * Runtime.exec, ProcessBuilder.start, ClassLoader.defineClass, Cipher.doFinal.
 * Deliberately does NOT check reflection invoke / getDeclaredMethod — too common
 * in legitimate code.
 */
public final class BytecodeMaliceCheck {

    private BytecodeMaliceCheck() {}

    /**
     * Returns true if the bytecode contains any high-confidence malicious API call.
     *
     * <p><strong>Note on substring matching:</strong> the underlying {@code hasMethodCall}
     * matches method names as substrings (not exact equality), so "exec" will also match
     * "execute", "execCmd", etc. For the current owners (Runtime, ProcessBuilder, Cipher)
     * this is intentional and the false-positive risk is negligible. When adding new owner
     * checks in the future, verify that substring matching is still acceptable for that owner.
     *
     * @param ba bytecode analysis result; null is treated as no malice
     */
    public static boolean hasMalice(BytecodeAnalysis ba) {
        if (ba == null) return false;
        if (ba.hasMethodCall("java/lang/Runtime", "exec")) return true;
        if (ba.hasMethodCall("java/lang/ProcessBuilder", "start")) return true;
        if (ba.hasMethodCallByName("defineClass")) return true;
        if (ba.hasMethodCall("javax/crypto/Cipher", "doFinal")) return true;
        return false;
    }

    /** Resolves bytecode for className from context, then checks. Null/unavailable → false. */
    public static boolean hasMalice(String className, ScanContext ctx) {
        if (className == null || ctx == null) return false;
        return hasMalice(ctx.bytecodeOf(className));
    }

    /**
     * True only when the class's bytecode was actually read for analysis.
     *
     * <p>Callers that grant trust based on the <em>absence</em> of malice (e.g. suppression
     * rules) must distinguish "bytecode read and proven clean" from "bytecode could not be
     * read" — the latter is not evidence of cleanliness. {@link #hasMalice} alone cannot make
     * that distinction (both return false), so it must be paired with this check.
     */
    public static boolean hasReadableBytecode(String className, ScanContext ctx) {
        if (className == null || ctx == null) return false;
        return ctx.bytecodeOf(className) != null;
    }
}
