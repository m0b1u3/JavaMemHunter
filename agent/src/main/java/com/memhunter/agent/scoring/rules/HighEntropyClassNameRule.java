package com.memhunter.agent.scoring.rules;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.scoring.ScoringRule;

import java.util.HashMap;
import java.util.Map;

public class HighEntropyClassNameRule implements ScoringRule {
    private static final double THRESHOLD = 3.5d;

    public String name() { return "high-entropy-class-name"; }

    public int evaluate(Finding finding, ScanContext ctx) {
        if (finding == null || finding.className == null) return 0;
        String n = simpleName(finding.className);
        if (n.length() < 6) return 0;
        return entropy(n) > THRESHOLD ? 1 : 0;
    }

    private String simpleName(String className) {
        int dot = className.lastIndexOf('.');
        String simple = dot >= 0 ? className.substring(dot + 1) : className;
        int dollar = simple.lastIndexOf('$');
        return dollar >= 0 ? simple.substring(dollar + 1) : simple;
    }

    private double entropy(String s) {
        Map<Character, Integer> counts = new HashMap<>();
        for (char c : s.toCharArray()) counts.put(c, counts.getOrDefault(c, 0) + 1);
        double e = 0d;
        for (Integer count : counts.values()) {
            double p = (double) count / s.length();
            e -= p * (Math.log(p) / Math.log(2));
        }
        return e;
    }
}
