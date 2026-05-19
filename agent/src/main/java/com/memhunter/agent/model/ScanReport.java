package com.memhunter.agent.model;

import java.util.ArrayList;
import java.util.List;

public class ScanReport {

    public String scanId;
    public String timestamp;
    public Target target = new Target();
    public Summary summary = new Summary();
    public List<Finding> findings = new ArrayList<>();
    public List<PartialError> partialErrors = new ArrayList<>();

    public static class Target {
        public long pid;
        public String javaVersion;
        public String os;
    }

    public static class Summary {
        public int totalFindings;
        public int critical;
        public int high;
        public int suspicious;
        public int low;
    }

    public static class PartialError {
        public String scanner;
        public String reason;

        public PartialError() {}

        public PartialError(String scanner, String reason) {
            this.scanner = scanner;
            this.reason = reason;
        }
    }
}
