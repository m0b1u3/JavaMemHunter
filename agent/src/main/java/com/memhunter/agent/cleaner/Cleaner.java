package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;

/**
 * Pluggable cleaner contract.
 *
 * <p>Contract for {@link #plan(Finding, boolean)}:
 * <ul>
 *   <li>Returns a populated {@link CleanPlan} when the finding can be located
 *       and passes type/score gating.</li>
 *   <li>Returns {@code null} when the finding cannot be located on a re-scan,
 *       is of the wrong type for this cleaner, or fails the score threshold
 *       without {@code forced=true}. The caller is responsible for translating
 *       a {@code null} into a user-visible {@link CleanResult} failure.</li>
 * </ul>
 */
public interface Cleaner {
    /** Build the dry-run plan + populate backup. Does NOT mutate runtime. */
    CleanPlan plan(Finding finding, boolean forced);

    /** Execute Phase C/D/E (later tasks). */
    CleanResult execute(CleanPlan plan, boolean forced);
}
