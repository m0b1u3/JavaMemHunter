package com.memhunter.attach;

import com.memhunter.agent.model.CleanPlan;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

public class CleanInteractor {

    public boolean promptYes(InputStream input, PrintStream output, CleanPlan plan) {
        if (output != null && plan != null) {
            output.println("Clean plan:");
            output.println("  findingId: " + nullToEmpty(plan.findingId));
            output.println("  filterName: " + nullToEmpty(plan.filterName));
            output.println("  filterClass: " + nullToEmpty(plan.filterClass));
            output.println("  contextPath: " + nullToEmpty(plan.contextPath));
            output.println("  score: " + plan.score);
            output.println("  level: " + nullToEmpty(plan.level));
            output.println("Type yes to confirm:");
        }
        if (input == null) {
            return false;
        }
        try {
            String line = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8)).readLine();
            return "yes".equals(line);
        } catch (IOException e) {
            return false;
        }
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
