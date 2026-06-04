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
                    StringBuilder line = new StringBuilder("  [" + level + "] " + type
                            + "  " + className + "  score=" + score);
                    appendLocation(line, type, f.path("attributes"));
                    out.println(line.toString());
                }
            }
        }
        out.println("[memhunter] full report: " + reportPath);
    }

    private static void appendLocation(StringBuilder line, String type, JsonNode attrs) {
        if (attrs == null || attrs.isMissingNode() || !attrs.isObject()) return;
        if ("tomcat-filter".equals(type)) {
            appendListPath(line, attrs.path("urlPatterns"), Integer.MAX_VALUE);
        } else if ("tomcat-servlet".equals(type)) {
            appendListPath(line, attrs.path("mappings"), Integer.MAX_VALUE);
        } else if ("spring-mapping".equals(type)) {
            JsonNode p = attrs.path("pattern");
            if (!p.isMissingNode() && !p.isNull() && !p.asText("").isEmpty()) {
                line.append("  path=").append(p.asText());
            }
        } else if ("spring-interceptor".equals(type)) {
            appendListPath(line, attrs.path("includePatterns"), Integer.MAX_VALUE);
            String exStr = formatList(attrs.path("excludePatterns"), Integer.MAX_VALUE);
            if (exStr != null) line.append("  exclude=").append(exStr);
        } else if ("agent-bytecode-tampered".equals(type)) {
            appendListPath(line, attrs.path("injectedStrings"), 5);
        } else if (type != null && type.startsWith("tomcat-listener-")) {
            JsonNode k = attrs.path("listenerKind");
            if (!k.isMissingNode() && !k.isNull() && !k.asText("").isEmpty()) {
                line.append("  trigger=").append(k.asText());
            }
        } else if ("tomcat-valve".equals(type)) {
            JsonNode idx = attrs.path("pipelineIndex");
            if (!idx.isMissingNode() && !idx.isNull()) {
                line.append("  pipeline=").append(idx.asText());
            }
        } else if ("agent-transformer".equals(type)) {
            JsonNode c = attrs.path("transformerClass");
            if (!c.isMissingNode() && !c.isNull() && !c.asText("").isEmpty()) {
                line.append("  class=").append(c.asText());
            }
        }
    }

    private static void appendListPath(StringBuilder line, JsonNode listNode, int max) {
        String s = formatList(listNode, max);
        if (s != null) line.append("  path=").append(s);
    }

    private static String formatList(JsonNode node, int max) {
        if (node == null || node.isMissingNode() || node.isNull()) return null;
        if (node.isArray()) {
            int n = node.size();
            if (n == 0) return null;
            StringBuilder sb = new StringBuilder("[");
            int shown = Math.min(n, max);
            for (int i = 0; i < shown; i++) {
                if (i > 0) sb.append(", ");
                sb.append(node.get(i).asText());
            }
            if (n > max) sb.append(", ...(+").append(n - max).append(" more)");
            sb.append("]");
            return sb.toString();
        }
        String t = node.asText("");
        if (t.isEmpty()) return null;
        return "[" + t + "]";
    }
}
