package com.memhunter.agent;

import com.memhunter.agent.model.Finding;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Merges findings that refer to the same class. Findings with a null className are not merged
 * (identity cannot be established) and are kept as-is. For each group sharing a className the
 * "richest" finding is kept: highest score, then (on tie) the one carrying an access-path
 * attribute, then (still tied) the earliest in input order. Other findings in the group are
 * dropped. Output order: each className in first-seen order, then the null-className findings.
 */
public final class FindingDeduplicator {

    private FindingDeduplicator() {}

    private static final String[] PATH_KEYS = {
        "urlPatterns", "mappings", "jspPath", "pattern", "includePatterns", "injectedStrings"
    };

    public static List<Finding> dedupe(List<Finding> all) {
        List<Finding> result = new ArrayList<>();
        if (all == null) return result;
        Map<String, Finding> best = new LinkedHashMap<>();
        List<Finding> nullClass = new ArrayList<>();
        for (Finding f : all) {
            if (f == null) continue;
            if (f.className == null) { nullClass.add(f); continue; }
            Finding cur = best.get(f.className);
            if (cur == null || isRicher(f, cur)) {
                best.put(f.className, f);
            }
        }
        result.addAll(best.values());
        result.addAll(nullClass);
        return result;
    }

    private static boolean isRicher(Finding candidate, Finding current) {
        if (candidate.score != current.score) return candidate.score > current.score;
        boolean candPath = hasPath(candidate);
        boolean curPath = hasPath(current);
        if (candPath != curPath) return candPath;
        return false;
    }

    private static boolean hasPath(Finding f) {
        if (f.attributes == null) return false;
        for (String k : PATH_KEYS) {
            Object v = f.attributes.get(k);
            if (v == null) continue;
            if (v instanceof Collection) {
                if (!((Collection<?>) v).isEmpty()) return true;
            } else if (!String.valueOf(v).isEmpty()) {
                return true;
            }
        }
        return false;
    }
}
