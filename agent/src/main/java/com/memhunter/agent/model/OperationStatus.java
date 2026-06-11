package com.memhunter.agent.model;

/**
 * Cross-process status of a clean/verify operation. The agent writes this to the attach-supplied
 * status file; the attach side reads it back to decide success/failure (v1.2). Public fields for
 * zero-config Jackson (de)serialization, matching the project's other model value types.
 */
public class OperationStatus {
    public boolean ok;
    public String command;
    public String id;
    public String message;
    public String error;
    public String stacktrace;
}
