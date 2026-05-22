package com.memhunter.agent.model;

import java.util.List;

public class CleanResult {

    public String findingId;
    public String failureReason;
    public boolean success;
    public boolean rolledBack;
    public boolean verifiedDisappeared;
    public List<String> executedSteps;
    public long executedAt;
}
