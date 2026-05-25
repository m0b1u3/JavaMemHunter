package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;

import java.util.Objects;

/**
 * Stateless validator that compares a persisted CleanPlan against a freshly
 * generated CleanPlan plus the confirm-time --force flag. Fail-fast on the
 * first mismatched field. v0.6.1 audit-chain gate.
 *
 * Compared fields (any mismatch -> stale):
 *   - findingId
 *   - filterClass
 *   - score
 *   - forced (must equal across persisted, fresh, AND confirmForceFlag)
 *
 * NOT compared (allowed to differ): generatedAt, evidenceDir, planFile, steps,
 *   level, urlPatterns, filterName, contextPath, type, rollbackSupported.
 */
public final class PlanReconciler {

    private PlanReconciler() {}

    public static void requireConsistent(CleanPlan persisted, CleanPlan fresh, boolean confirmForceFlag) {
        Objects.requireNonNull(persisted, "persisted plan must not be null");
        Objects.requireNonNull(fresh, "fresh plan must not be null");

        if (!Objects.equals(persisted.findingId, fresh.findingId)) {
            throw stale("findingId", persisted.findingId, fresh.findingId);
        }
        if (!Objects.equals(persisted.targetClass, fresh.targetClass)) {
            throw stale("targetClass", persisted.targetClass, fresh.targetClass);
        }
        if (persisted.score != fresh.score) {
            throw stale("score", persisted.score, fresh.score);
        }
        if (persisted.forced != fresh.forced || persisted.forced != confirmForceFlag) {
            throw new PlanStaleException(
                "plan stale: forced mismatch (persisted=" + persisted.forced
                + ", fresh=" + fresh.forced
                + ", confirmFlag=" + confirmForceFlag + ")"
            );
        }
    }

    private static PlanStaleException stale(String field, Object persisted, Object fresh) {
        return new PlanStaleException(
            "plan stale: " + field + " mismatch (persisted=" + persisted + ", fresh=" + fresh + ")"
        );
    }
}
