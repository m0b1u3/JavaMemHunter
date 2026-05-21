package com.memhunter.agent.scoring.bytecode;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Bytecode scan result for a single class. Captures all method calls made by the class,
 * formatted as "owner#name" strings (e.g. "java/lang/Runtime#exec").
 *
 * <p>The {@code methodCalls} set is unmodifiable: attempts to mutate it throw
 * {@link UnsupportedOperationException}.
 */
public class BytecodeAnalysis {

    /** Immutable view of method call strings. */
    public final Set<String> methodCalls;

    public BytecodeAnalysis(Set<String> methodCalls) {
        this.methodCalls = Collections.unmodifiableSet(new HashSet<>(methodCalls));
    }

    /**
     * True if any method call matches owner exactly AND name CONTAINS namePattern.
     *
     * <p>Note: name match is substring, not equals. {@code "exec"} matches
     * {@code "exec"}, {@code "execute"}, {@code "execAsync"}. This is intentional
     * for the broad detection use case where attackers may use minor name variations.
     */
    public boolean hasMethodCall(String owner, String namePattern) {
        for (String call : methodCalls) {
            int sep = call.indexOf('#');
            if (sep < 0) continue;
            if (call.substring(0, sep).equals(owner)
                    && call.substring(sep + 1).contains(namePattern)) return true;
        }
        return false;
    }

    /**
     * True if any method call's name contains namePattern (substring), regardless of owner.
     */
    public boolean hasMethodCallByName(String namePattern) {
        for (String call : methodCalls) {
            int sep = call.indexOf('#');
            if (sep < 0) continue;
            if (call.substring(sep + 1).contains(namePattern)) return true;
        }
        return false;
    }

    /**
     * True if any method call's owner starts with the given prefix.
     * Useful for matching any class under a parent package or for nested classes
     * (e.g. {@code "java/util/Base64"} matches both {@code Base64} and {@code Base64$Decoder}).
     */
    public boolean hasMethodCallByOwnerPrefix(String ownerPrefix) {
        if (ownerPrefix == null) return false;
        for (String call : methodCalls) {
            int sep = call.indexOf('#');
            if (sep < 0) continue;
            if (call.substring(0, sep).startsWith(ownerPrefix)) return true;
        }
        return false;
    }
}
