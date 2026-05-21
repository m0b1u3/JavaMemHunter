package com.memhunter.agent.scoring.bytecode;

import java.util.Set;

/**
 * Bytecode scan result for a single class. Captures all method calls made by the class,
 * formatted as "owner#name" strings (e.g. "java/lang/Runtime#exec").
 */
public class BytecodeAnalysis {

    public final Set<String> methodCalls;

    public BytecodeAnalysis(Set<String> methodCalls) {
        this.methodCalls = methodCalls;
    }

    /** True if any method call matches owner exactly AND name contains namePattern. */
    public boolean hasMethodCall(String owner, String namePattern) {
        for (String call : methodCalls) {
            int sep = call.indexOf('#');
            if (sep < 0) continue;
            if (call.substring(0, sep).equals(owner)
                    && call.substring(sep + 1).contains(namePattern)) return true;
        }
        return false;
    }

    /** True if any method call's name contains namePattern, regardless of owner. */
    public boolean hasMethodCallByName(String namePattern) {
        for (String call : methodCalls) {
            int sep = call.indexOf('#');
            if (sep < 0) continue;
            if (call.substring(sep + 1).contains(namePattern)) return true;
        }
        return false;
    }
}
