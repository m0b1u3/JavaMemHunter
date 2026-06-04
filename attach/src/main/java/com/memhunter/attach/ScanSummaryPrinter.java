package com.memhunter.attach;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.PrintStream;

/**
 * Reads a scan report JSON and prints a concise summary to the user's attach-side console:
 * the per-level counts, then each critical/high/suspicious finding on one line
 * ({@code [level] type className score=N}); "low" findings are counted only, not listed.
 * The full JSON report (which still contains every finding for forensics) is referenced by path.
 *
 * <p>Failure to read or parse the report never throws — it prints a single degraded line so the
 * scan command still succeeds.
 */
public final class ScanSummaryPrinter {

    private ScanSummaryPrinter() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String[] SHOWN_LEVELS = {"critical", "high", "suspicious"};

    public static void print(PrintStream out, String reportPath, int pid) {
        JsonNode root;
        try {
            root = MAPPER.readTree(new File(reportPath));
            if (root == null) throw new IllegalStateException("empty report");
        } catch (Throwable t) {
            out.println("[memhunter] scan finished, report at " + reportPath
                    + " (summary unavailable: " + t.getClass().getSimpleName() + ")");
            return;
        }

        JsonNode summary = root.path("summary");
        out.println("[memhunter] scan summary (PID " + pid + "):");
        out.println("  critical: " + summary.path("critical").asInt(0)
                + "  high: " + summary.path("high").asInt(0)
                + "  suspicious: " + summary.path("suspicious").asInt(0)
                + "  low: " + summary.path("low").asInt(0));

        JsonNode findings = root.path("findings");
        if (findings.isArray()) {
            for (String level : SHOWN_LEVELS) {
                for (JsonNode f : findings) {
                    if (!level.equals(f.path("level").asText(""))) continue;
                    String type = f.path("type").asText("");
                    JsonNode cn = f.path("className");
                    String className = (cn.isNull() || cn.isMissingNode()) ? "<null>" : cn.asText();
                    int score = f.path("score").asInt(0);
                    out.println("  [" + level + "] " + type + "  " + className + "  score=" + score);
                }
            }
        }
        out.println("[memhunter] full report: " + reportPath);
    }
}
