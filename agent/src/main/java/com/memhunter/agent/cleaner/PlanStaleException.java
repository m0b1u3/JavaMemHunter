package com.memhunter.agent.cleaner;

/**
 * Thrown when the persisted clean-plan.json disagrees with a freshly-generated
 * plan or with the confirm-time --force flag.
 *
 * Carrying a precise field-mismatch message in the exception message is part of
 * v0.6.1's audit-chain contract: operators reviewing evidence must be able to
 * see exactly which field failed reconciliation.
 */
public class PlanStaleException extends RuntimeException {
    public PlanStaleException(String message) {
        super(message);
    }
}
