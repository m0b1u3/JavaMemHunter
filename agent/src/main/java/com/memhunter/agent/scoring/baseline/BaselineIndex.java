package com.memhunter.agent.scoring.baseline;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Immutable set of Finding IDs from a baseline scan report.
 * Used by BaselineNewRule to detect findings not present in the baseline.
 */
public class BaselineIndex {

    private final Set<String> findingIds;

    public BaselineIndex(Set<String> findingIds) {
        this.findingIds = Collections.unmodifiableSet(new HashSet<>(findingIds));
    }

    public static BaselineIndex empty() {
        return new BaselineIndex(Collections.<String>emptySet());
    }

    public boolean contains(String findingId) {
        return findingId != null && findingIds.contains(findingId);
    }

    public boolean isEmpty() {
        return findingIds.isEmpty();
    }

    public int size() {
        return findingIds.size();
    }
}
