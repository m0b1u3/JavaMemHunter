package com.memhunter.attach;

import com.memhunter.agent.cleaner.CleanPlanReader;
import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.verify.VerifyExecutor;

import java.io.InputStream;
import java.io.PrintStream;
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
            CleanPlan plan = CleanPlanReader.read(evidenceDir.resolve("evidence").resolve(id)
                    .resolve("clean-plan.json"));
            if (!new CleanInteractor().promptYes(input, out, plan)) {
                err.println("[memhunter] clean cancelled");
                return 1;
            }
            executor.run(pid, agentJar, agentArgs.toString());
            return printCleanResult(out, evidenceDir, id) ? 0 : 1;
        }
        executor.run(pid, agentJar, agentArgs.toString());
        if ("verify".equals(command)) {
            return printVerifyResult(out, evidenceDir(options), requireOption(options, "id")) ? 0 : 1;
        }
        return 0;
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
