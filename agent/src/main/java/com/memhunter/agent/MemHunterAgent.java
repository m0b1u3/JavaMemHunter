package com.memhunter.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.report.JsonReportWriter;
import com.memhunter.agent.scanner.ClassScanner;

import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class MemHunterAgent {

    public static void agentmain(String agentArgs, Instrumentation inst) {
        try {
            AgentArgs args = AgentArgs.parse(agentArgs);
            if (!"scan".equals(args.command)) {
                System.err.println("[memhunter] unsupported command: " + args.command);
                return;
            }

            ScanReport report = new ScanReport();
            report.scanId = "scan-" + UUID.randomUUID().toString().substring(0, 8);
            report.timestamp = Instant.now().toString();
            report.target.pid = pidOfSelf();
            report.target.javaVersion = System.getProperty("java.version");
            report.target.os = System.getProperty("os.name");

            List<Finding> findings = new ClassScanner(inst).scan();
            report.findings = findings;
            report.summary.totalFindings = findings.size();
            for (Finding f : findings) {
                if ("critical".equals(f.level)) report.summary.critical++;
                else if ("high".equals(f.level)) report.summary.high++;
                else if ("suspicious".equals(f.level)) report.summary.suspicious++;
                else report.summary.low++;
            }

            String output = args.options.getOrDefault("output",
                    System.getProperty("java.io.tmpdir") + "/memhunter-report-" + report.scanId + ".json");
            new JsonReportWriter().write(report, output);
            System.out.println("[memhunter] scan finished, findings=" + findings.size()
                    + ", report=" + output);
        } catch (Throwable t) {
            System.err.println("[memhunter] agent failed: " + t.getMessage());
            t.printStackTrace(System.err);
        }
    }

    private static long pidOfSelf() {
        try {
            String name = ManagementFactory.getRuntimeMXBean().getName();
            return Long.parseLong(name.split("@")[0]);
        } catch (Throwable t) {
            return -1;
        }
    }
}
