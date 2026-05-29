package com.memhunter.agent.cleaner;

import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Template base for Tomcat cleaners. Shares:
 *  - Phase A (re-scan + type/score gating)
 *  - Phase D (3-label release: destroy-ran / no-release-method / destroy-threw)
 *  - Phase E (re-scan verify + auto-rollback)
 *  - plan() and execute() orchestration
 *
 * Subclasses provide:
 *  - supportsType(String) — type-match predicate
 *  - locateOnRescan(String findingId) — type-specific scanner re-run
 *  - buildDetails(Finding) — type-specific details map
 *  - doPhaseB(Finding) — populate backup + rollback strategy
 *  - doPhaseC() — atomic copy-replace
 *  - phaseDLabels() — return one or more step labels (Servlet returns 2: unload + destroy)
 *  - stillPresentOnRescan(String findingId) — Phase E predicate
 *  - phaseSteps() — list of plan-text steps for the CleanPlan.steps field
 *
 * <p><b>Thread-safety and reuse:</b> Each cleaner instance carries per-finding
 * state ({@code currentFinding}, {@code currentTargetName}, {@code rollback}).
 * Callers MUST construct a fresh cleaner per dispatch — calling {@code execute()}
 * twice on the same instance, or reusing an instance across different findings,
 * is unsupported and will produce undefined behaviour. The CleanerRegistry
 * factory pattern enforces this for production code paths.
 */
public abstract class AbstractTomcatCleaner implements Cleaner {

    protected final Object standardContext;
    protected RollbackStrategy rollback;
    protected String currentTargetName;
    protected String currentTargetClass;
    protected Finding currentFinding;

    protected AbstractTomcatCleaner(Object standardContext) {
        this.standardContext = standardContext;
    }

    protected abstract boolean supportsType(String type);
    protected abstract Finding locateOnRescan(String findingId);
    protected abstract Map<String, Object> buildDetails(Finding finding);
    protected abstract void doPhaseB(Finding finding);
    protected abstract void doPhaseC() throws CleanExecutionException;
    protected abstract List<String> phaseDLabels();
    protected abstract boolean stillPresentOnRescan(String findingId);
    protected abstract List<String> phaseSteps();

    @Override
    public final CleanPlan plan(Finding finding, boolean forced) {
        if (finding == null) return null;
        if (!supportsType(finding.type)) return null;
        // Score gate uses the input finding's score (carried from the original
        // scan pipeline). The re-scan only verifies presence, not risk.
        if (finding.score < 7 && !forced) return null;

        // Phase A: re-scan and confirm presence
        Finding fresh = locateOnRescan(finding.id);
        if (fresh == null) return null;

        // Preserve score/level from the original finding. Scanner re-runs only
        // verify presence; they do not invoke RuleEngine, so fresh.score is 0 and
        // fresh.level is null. We mutate the local `fresh` Finding directly —
        // this is safe because every scanner constructs a new Finding instance
        // per scan; no shared reference is updated.
        if (fresh.score == 0) fresh.score = finding.score;
        if (fresh.level == null) fresh.level = finding.level;

        currentFinding = fresh;
        currentTargetName = fresh.name;
        currentTargetClass = fresh.className;
        doPhaseB(fresh);

        CleanPlan p = new CleanPlan();
        p.findingId = fresh.id;
        p.type = fresh.type;
        p.targetName = fresh.name;
        p.targetClass = fresh.className;
        p.contextPath = String.valueOf(fresh.attributes.getOrDefault("contextPath", ""));
        p.score = fresh.score;
        p.level = fresh.level;
        p.forced = forced;
        p.rollbackSupported = true;
        p.steps = phaseSteps();
        p.details = buildDetails(fresh);
        p.generatedAt = System.currentTimeMillis();
        return p;
    }

    @Override
    public final CleanResult execute(CleanPlan plan, boolean forced) {
        CleanResult result = new CleanResult();
        result.findingId = plan == null ? null : plan.findingId;
        result.executedSteps = new ArrayList<>();
        result.executedAt = System.currentTimeMillis();

        if (plan == null || currentFinding == null || rollback == null) {
            result.success = false;
            result.failureReason = "plan() must be called first";
            return result;
        }

        // Phase C
        try {
            doPhaseC();
            result.executedSteps.add("phase-C: atomic copy-replace done");
        } catch (CleanExecutionException ce) {
            result.success = false;
            result.rolledBack = ce.didMutate();
            result.failureReason = "Phase C failed: " + ce.getMessage();
            result.executedSteps.add(ce.didMutate()
                    ? "phase-C: FAILED, rolled back"
                    : "phase-C: FAILED before mutation");
            return result;
        } catch (RollbackFailedException rf) {
            result.success = false;
            result.rolledBack = false;
            result.failureReason = "ROLLBACK FAILED: " + rf.getMessage();
            result.executedSteps.add("phase-C: FAILED + ROLLBACK FAILED");
            return result;
        }

        // Phase D
        List<String> dLabels = phaseDLabels();
        if (dLabels != null) {
            result.executedSteps.addAll(dLabels);
        }

        // Phase E: re-scan and verify
        if (stillPresentOnRescan(plan.findingId)) {
            try {
                rollback.restore();
                result.success = false;
                result.rolledBack = true;
                result.verifiedDisappeared = false;
                result.failureReason = "finding still present after Phase C";
                result.executedSteps.add("phase-E: verify FAILED, rolled back");
                return result;
            } catch (RollbackFailedException rf) {
                result.success = false;
                result.rolledBack = false;
                result.verifiedDisappeared = false;
                result.failureReason = "post-verify rollback failed: " + rf.getMessage();
                result.executedSteps.add("phase-E: verify FAILED + ROLLBACK FAILED");
                return result;
            }
        }

        result.success = true;
        result.verifiedDisappeared = true;
        result.executedSteps.add("phase-E: verified disappeared");
        return result;
    }

    /**
     * Phase D helper: try each named method in order on target; return the first
     * 3-label step describing the outcome.
     */
    protected final String releaseTargetByConvention(Object target, String... methodNames) {
        if (target == null) return "phase-D: no-release-method";
        for (String name : methodNames) {
            try {
                Method m = target.getClass().getMethod(name);
                m.invoke(target);
                return "phase-D: destroy-ran";
            } catch (NoSuchMethodException nse) {
                // try next
            } catch (InvocationTargetException ite) {
                Throwable cause = ite.getCause() != null ? ite.getCause() : ite;
                return phaseDThrew(cause);
            } catch (Throwable t) {
                return phaseDThrew(t);
            }
        }
        return "phase-D: no-release-method";
    }

    private static String phaseDThrew(Throwable t) {
        String msg = t.getMessage() == null ? "" : t.getMessage();
        return "phase-D: destroy-threw: " + t.getClass().getSimpleName() + ": " + msg;
    }
}
