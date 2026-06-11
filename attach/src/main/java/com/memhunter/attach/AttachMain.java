package com.memhunter.attach;

import com.memhunter.agent.cleaner.CleanPlanReader;
import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.verify.VerifyExecutor;

import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class AttachMain {

    public static void main(String[] args) throws Exception {
        int code = run(args, System.in, System.out, System.err, new AttachExecutor());
        if (code != 0) {
            System.exit(code);
        }
    }

    static int run(String[] args, InputStream input, PrintStream out, PrintStream err,
                   AttachExecutor executor) throws Exception {
        if (args.length == 0) {
            printUsage(err);
            return 1;
        }
        String cmd = args[0];
        if ("list".equals(cmd)) {
            new JvmProcessLister().printAll();
            return 0;
        }
        if (args.length < 3) {
            printUsage(err);
            return 1;
        }
        String pid = args[0];
        String agentJar = args[1];
        StringBuilder agentArgs = new StringBuilder(args[2]);
        for (int i = 3; i < args.length; i++) {
            agentArgs.append(' ').append(args[i]);
        }
        String command = args[2];
        Map<String, String> options = parseOptions(args, 3);
        if ("clean".equals(command) && options.containsKey("confirm")) {
            String id = requireOption(options, "id");
            Path evidenceDir = evidenceDir(options);
            Path planFile = evidenceDir.resolve("evidence").resolve(id).resolve("clean-plan.json");
            if (!Files.exists(planFile)) {
                err.println("[memhunter] plan file not found at " + planFile
                        + "; run --dry-run first to generate the plan");
                return 2;
            }
            CleanPlan plan = CleanPlanReader.read(planFile);
            if (!new CleanInteractor().promptYes(input, out, plan)) {
                err.println("[memhunter] clean cancelled");
                return 1;
            }
            String statusFile = newStatusFilePath(pid);
            executor.run(pid, agentJar, agentArgs.toString() + " --status-file " + statusFile);
            if (reportedFailure(out, statusFile)) return 2;
            return printCleanResult(out, evidenceDir, id) ? 0 : 1;
        }
        if ("scan".equals(command)) {
            String reportPath = resolveScanOutput(options);
            String scanArgs;
            if (options.containsKey("output")) {
                // reportPath is guaranteed space-free by resolveScanOutput; the agent arg pipeline
                // splits on whitespace so paths with spaces are rejected upstream.
                scanArgs = agentArgs.toString().replaceFirst(
                        "--output\\s+\\S+",
                        java.util.regex.Matcher.quoteReplacement("--output " + reportPath));
            } else {
                scanArgs = agentArgs.toString() + " --output " + reportPath;
            }
            executor.run(pid, agentJar, scanArgs);
            ScanSummaryPrinter.print(out, reportPath, parseIntSafe(pid));
            return 0;
        }
        String statusFile = newStatusFilePath(pid);
        executor.run(pid, agentJar, agentArgs.toString() + " --status-file " + statusFile);
        if (reportedFailure(out, statusFile)) return 2;
        if ("verify".equals(command)) {
            return printVerifyResult(out, evidenceDir(options), requireOption(options, "id")) ? 0 : 1;
        }
        return 0;
    }

    static String resolveScanOutput(java.util.Map<String, String> options) {
        String userOut = options.get("output");
        String abs;
        if (userOut != null && !"true".equals(userOut)) {  // "true" = parseOptions sentinel for flag-only --output
            abs = new java.io.File(userOut).getAbsolutePath();
        } else {
            abs = new java.io.File("memhunter-scan-" + System.currentTimeMillis() + ".json")
                    .getAbsolutePath();
        }
        if (abs.indexOf(' ') >= 0) {
            throw new IllegalArgumentException(
                "--output path must not contain spaces (agent arg parsing splits on whitespace): " + abs);
        }
        return abs;
    }

    private static int parseIntSafe(String s) {
        if (s == null) return -1;
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return -1; }
    }

    private static void printUsage(PrintStream err) {
        err.println("Usage:");
        err.println("  java -jar memhunter-attach.jar list");
        err.println("  java -jar memhunter-attach.jar <pid> <agent-jar> scan [--output <file>]");
        err.println("  java -jar memhunter-attach.jar <pid> <agent-jar> clean --id <id> --dry-run [--evidence-dir <dir>]");
        err.println("  java -jar memhunter-attach.jar <pid> <agent-jar> clean --id <id> --confirm [--force] [--evidence-dir <dir>]");
        err.println("  java -jar memhunter-attach.jar <pid> <agent-jar> verify --id <id> [--evidence-dir <dir>]");
    }

    private static Map<String, String> parseOptions(String[] args, int start) {
        Map<String, String> options = new HashMap<>();
        for (int i = start; i < args.length; i++) {
            String token = args[i];
            if (!token.startsWith("--")) continue;
            String key = token.substring(2);
            if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                options.put(key, args[++i]);
            } else {
                options.put(key, "true");
            }
        }
        return options;
    }

    private static String requireOption(Map<String, String> options, String key) {
        String value = options.get(key);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("missing --" + key);
        }
        return value;
    }

    private static Path evidenceDir(Map<String, String> options) {
        return Paths.get(options.getOrDefault("evidence-dir", "."));
    }

    private static String newStatusFilePath(String pid) {
        String tmp = System.getProperty("java.io.tmpdir");
        String name = "memhunter-status-" + pid + "-" + System.currentTimeMillis() + ".json";
        String abs = new java.io.File(tmp, name).getAbsolutePath();
        if (abs.indexOf(' ') >= 0) {
            abs = new java.io.File("memhunter-status-" + pid + "-"
                    + System.currentTimeMillis() + ".json").getAbsolutePath();
        }
        return abs;
    }

    /** Returns true if the agent reported failure; prints the reason. False otherwise (incl. no file). */
    private static boolean reportedFailure(PrintStream out, String statusFile) {
        com.memhunter.agent.model.OperationStatus status = StatusFileReader.read(statusFile);
        try {
            if (statusFile != null) new java.io.File(statusFile).delete();
        } catch (Throwable ignored) {}
        if (status == null) return false;
        if (!status.ok) {
            out.println("[memhunter] operation FAILED: " + status.error);
            return true;
        }
        return false;
    }

    private static boolean printCleanResult(PrintStream out, Path evidenceDir, String id) throws Exception {
        Path file = evidenceDir.resolve("evidence").resolve(id).resolve("clean-result.json");
        CleanResult result = CleanPlanReader.readResult(file);
        out.println("[memhunter] clean result: id=" + id
                + ", success=" + result.success
                + ", verifiedDisappeared=" + result.verifiedDisappeared
                + ", rolledBack=" + result.rolledBack);
        return result.success;
    }

    private static boolean printVerifyResult(PrintStream out, Path evidenceDir, String id) throws Exception {
        Path file = evidenceDir.resolve("evidence").resolve(id).resolve("verify-result.json");
        VerifyExecutor.VerifyResult result = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(file.toFile(), VerifyExecutor.VerifyResult.class);
        out.println("[memhunter] verify result: id=" + id
                + ", stillPresent=" + result.stillPresent);
        return !result.stillPresent;
    }
}
