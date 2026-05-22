package com.memhunter.agent.cleaner;

public class RollbackFailedException extends RuntimeException {
    public RollbackFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
