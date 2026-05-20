package com.memhunter.agent.scoring;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Whitelist {

    private final List<String> frameworkPackages = new ArrayList<>();
    private final List<String> businessPackages = new ArrayList<>();
    private final List<String> apmAgents = new ArrayList<>();
    private final List<String> codesourcePaths = new ArrayList<>();

    public static Whitelist defaults() {
        Whitelist w = new Whitelist();
        Collections.addAll(w.frameworkPackages, DefaultWhitelist.FRAMEWORK_PACKAGES);
        Collections.addAll(w.apmAgents, DefaultWhitelist.APM_AGENTS);
        Collections.addAll(w.codesourcePaths, DefaultWhitelist.CODESOURCE_PATHS);
        return w;
    }

    public void loadFromFile(String path) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                int colon = trimmed.indexOf(':');
                if (colon <= 0 || colon == trimmed.length() - 1) {
                    System.err.println("[memhunter] whitelist: skipping malformed line: " + trimmed);
                    continue;
                }
                addEntry(trimmed.substring(0, colon).trim(), trimmed.substring(colon + 1).trim());
            }
        }
    }

    private void addEntry(String type, String value) {
        if ("framework".equals(type)) frameworkPackages.add(value);
        else if ("business".equals(type)) businessPackages.add(value);
        else if ("agent".equals(type)) apmAgents.add(value);
        else if ("codesource".equals(type)) codesourcePaths.add(value);
        else System.err.println("[memhunter] whitelist: unknown type '" + type + "', skipping");
    }

    public boolean isFrameworkPackage(String className) {
        return className != null && startsWithAny(className, frameworkPackages);
    }

    public boolean isBusinessPackage(String className) {
        return className != null && startsWithAny(className, businessPackages);
    }

    public boolean isApmAgent(String className) {
        if (className == null) return false;
        for (String marker : apmAgents) {
            if (className.startsWith(marker) || className.contains(marker)) return true;
        }
        return false;
    }

    public boolean isTrustedCodeSource(String codeSource) {
        if (codeSource == null) return false;
        for (String path : codesourcePaths) {
            if (codeSource.contains(path)) return true;
        }
        return false;
    }

    public List<String> commonClassLoaders() {
        return Arrays.asList(DefaultWhitelist.COMMON_CLASSLOADERS);
    }

    private static boolean startsWithAny(String value, List<String> prefixes) {
        for (String prefix : prefixes) {
            if (value.startsWith(prefix)) return true;
        }
        return false;
    }
}
