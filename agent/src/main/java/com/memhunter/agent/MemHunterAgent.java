package com.memhunter.agent;

import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.report.JsonReportWriter;
import com.memhunter.agent.scanner.ClassScanner;
import com.memhunter.agent.scanner.spring.SpringScanner;
import com.memhunter.agent.scanner.tomcat.TomcatScanner;
import com.memhunter.agent.scoring.RuleEngine;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.util.ReflectUtil;

import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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

            Whitelist whitelist = Whitelist.defaults();
            String whitelistFile = args.options.get("whitelist");
            if (whitelistFile != null) {
                try {
                    whitelist.loadFromFile(whitelistFile);
                } catch (Throwable t) {
                    report.partialErrors.add(new ScanReport.PartialError(
                            "WhitelistLoader", "failed to load " + whitelistFile + ": " + t.getMessage()));
                }
            }
            boolean explain = "true".equals(args.options.get("explain"));

            List<Finding> all = new ArrayList<>();

            // 1. Class-level scan (v0.1 behavior)
            all.addAll(new ClassScanner(inst).scan());

            // 2. Tomcat container scan (locate once, scan once, reuse contexts for Spring)
            TomcatScanner tomcat = new TomcatScanner();
            List<Object> tomcatContexts = tomcat.locateContexts(inst, report);
            List<Finding> tomcatFindings = tomcat.scanContexts(tomcatContexts, report);
            all.addAll(tomcatFindings);

            // 3. Spring runtime scan
            List<Object> tomcatServletInstances = extractServletInstances(tomcatContexts);
            SpringScanner spring = new SpringScanner();
            List<Finding> springFindings = spring.scan(tomcatContexts, tomcatServletInstances, report);
            all.addAll(springFindings);

            // 4. v0.3 scoring
            Object appCtx = pickFirstAppContext(tomcatServletInstances);
            new RuleEngine().evaluate(all, new ScanContext(appCtx, whitelist, explain));

            report.findings = all;
            report.summary.totalFindings = all.size();
            for (Finding f : all) {
                if ("critical".equals(f.level)) report.summary.critical++;
                else if ("high".equals(f.level)) report.summary.high++;
                else if ("suspicious".equals(f.level)) report.summary.suspicious++;
                else report.summary.low++;
            }

            String output = args.options.getOrDefault("output",
                    System.getProperty("java.io.tmpdir") + "/memhunter-report-" + report.scanId + ".json");
            new JsonReportWriter().write(report, output);
            System.out.println("[memhunter] scan finished, findings=" + all.size()
                    + ", report=" + output);
        } catch (Throwable t) {
            System.err.println("[memhunter] agent failed: " + t.getMessage());
            t.printStackTrace(System.err);
        }
    }

    private static List<Object> extractServletInstances(List<Object> tomcatContexts) {
        List<Object> instances = new ArrayList<>();
        for (Object ctx : tomcatContexts) {
            Optional<Object> children = ReflectUtil.tryInvoke(ctx, "findChildren");
            if (!children.isPresent() || !(children.get() instanceof Object[])) continue;
            for (Object wrapper : (Object[]) children.get()) {
                if (wrapper == null) continue;
                Optional<Object> servlet = ReflectUtil.tryInvoke(wrapper, "getServlet");
                if (servlet.isPresent() && servlet.get() != null) {
                    instances.add(servlet.get());
                }
            }
        }
        return instances;
    }

    private static Object pickFirstAppContext(List<Object> servletInstances) {
        for (Object servlet : servletInstances) {
            if (!"org.springframework.web.servlet.DispatcherServlet"
                    .equals(servlet.getClass().getName())) continue;
            Optional<Object> appCtx = ReflectUtil.tryReadField(servlet, "webApplicationContext");
            if (appCtx.isPresent()) return appCtx.get();
        }
        return null;
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
