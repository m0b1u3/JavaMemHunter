package com.memhunter.agent;

import java.util.HashMap;
import java.util.Map;

public class AgentArgs {

    public final String command;
    public final Map<String, String> options;

    private AgentArgs(String command, Map<String, String> options) {
        this.command = command;
        this.options = options;
    }

    public static AgentArgs parse(String raw) {
        if (raw == null || raw.isEmpty()) {
            return new AgentArgs("scan", new HashMap<>());
        }
        String[] tokens = raw.split("\\s+");
        String command = tokens[0];
        Map<String, String> options = new HashMap<>();
        for (int i = 1; i < tokens.length; i++) {
            String t = tokens[i];
            if (t.startsWith("--") && i + 1 < tokens.length && !tokens[i + 1].startsWith("--")) {
                options.put(t.substring(2), tokens[i + 1]);
                i++;
            } else if (t.startsWith("--")) {
                options.put(t.substring(2), "true");
            }
        }
        return new AgentArgs(command, options);
    }
}
