package com.memhunter.agent.cleaner;

/**
 * Per-cleaner rollback contract. Implementations capture enough state in their
 * constructor to undo a single Phase C atomic copy-replace operation.
 * Throws RollbackFailedException only on catastrophic (unrecoverable) failures.
 */
public interface RollbackStrategy {
    void restore() throws RollbackFailedException;
}
