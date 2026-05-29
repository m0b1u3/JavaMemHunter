package com.memhunter.agent.cleaner;

/**
 * Thrown when Phase C cleaning fails. The didMutate flag tells the execute()
 * template whether runtime state was actually changed before the failure:
 *   - didMutate=true  : forward mutation partially applied, then rolled back
 *   - didMutate=false : failure before any mutation (e.g. backup not located),
 *                       so there was nothing to roll back
 */
public class CleanExecutionException extends RuntimeException {
    private final boolean didMutate;

    public CleanExecutionException(String message, boolean didMutate) {
        super(message);
        this.didMutate = didMutate;
    }

    public CleanExecutionException(String message, Throwable cause, boolean didMutate) {
        super(message, cause);
        this.didMutate = didMutate;
    }

    public boolean didMutate() {
        return didMutate;
    }
}
