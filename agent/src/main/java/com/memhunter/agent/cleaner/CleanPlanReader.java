package com.memhunter.agent.cleaner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Reads previously-persisted clean plan / result JSON files back into their models.
 * Used by the attach-side confirm flow (v0.6 design doc §3.3).
 */
public final class CleanPlanReader {

    private CleanPlanReader() {}

    public static CleanPlan read(Path planFile) throws IOException {
        return new ObjectMapper().readValue(planFile.toFile(), CleanPlan.class);
    }

    public static CleanResult readResult(Path resultFile) throws IOException {
        return new ObjectMapper().readValue(resultFile.toFile(), CleanResult.class);
    }
}
