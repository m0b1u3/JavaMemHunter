package com.memhunter.agent;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AgentArgs {

    public final String command;
    public final Map<String, String> options;

    private static final Set<String> KNOWN_OPTIONS = new HashSet<>();
    static {
        KNOWN_OPTIONS.add("output");
        KNOWN_OPTIONS.add("whitelist");
        KNOWN_OPTIONS.add("explain");
        KNOWN_OPTIONS.add("baseline");
        KNOWN_OPTIONS.add("id");
        KNOWN_OPTIONS.add("dry-run");
        KNOWN_OPTIONS.add("confirm");
        KNOWN_OPTIONS.add("force");
        KNOWN_OPTIONS.add("evidence-dir");
    }

    private AgentArgs(String command, Map<String, String> options) {
        this.command = command;
        this.options = options;
    }

    public static AgentArgs parse(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return new AgentArgs("scan", new HashMap<>());
        }
        String trimmed = raw.trim();
        String[] tokens = trimmed.split("\\s+");
        String command = tokens[0];
        Map<String, String> options = new HashMap<>();
        for (int i = 1; i < tokens.length; i++) {
            String t = tokens[i];
            String key = null;
            if (t.startsWith("--") && i + 1 < tokens.length && !tokens[i + 1].startsWith("--")) {
                key = t.substring(2);
                options.put(key, tokens[i + 1]);
                i++;
            } else if (t.startsWith("--")) {
                key = t.substring(2);
                options.put(key, "true");
            }
            if (key != null && !KNOWN_OPTIONS.contains(key)) {
                System.err.println("[memhunter] warning: unknown option --" + key);
            }
        }
        AgentArgs args = new AgentArgs(command, options);
        validate(args);
        return args;
    }

    private static void validate(AgentArgs args) {
        if ("clean".equals(args.command)) {
            boolean hasDryRun = args.options.containsKey("dry-run");
            boolean hasConfirm = args.options.containsKey("confirm");
            if (!args.options.containsKey("id")) {
                throw new IllegalArgumentException("clean requires --id");
            }
            if (!hasDryRun && !hasConfirm) {
                throw new IllegalArgumentException("clean requires either --dry-run or --confirm");
            }
            if (hasDryRun && hasConfirm) {
                throw new IllegalArgumentException("clean cannot combine --dry-run and --confirm");
            }
        } else if ("verify".equals(args.command)) {
            if (!args.options.containsKey("id")) {
                throw new IllegalArgumentException("verify requires --id");
            }
        }
    }
}
