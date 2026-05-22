package com.memhunter.agent;

import com.memhunter.agent.cleaner.CleanPlanReader;
import com.memhunter.agent.cleaner.EvidenceWriter;
import com.memhunter.agent.cleaner.TomcatFilterCleaner;
import com.memhunter.agent.model.CleanPlan;
import com.memhunter.agent.model.CleanResult;
import com.memhunter.agent.model.Finding;
import com.memhunter.agent.model.ScanContext;
import com.memhunter.agent.model.ScanReport;
import com.memhunter.agent.report.JsonReportWriter;
import com.memhunter.agent.scanner.ClassScanner;
import com.memhunter.agent.scanner.spring.SpringScanner;
import com.memhunter.agent.scanner.tomcat.TomcatScanner;
import com.memhunter.agent.scoring.RuleEngine;
import com.memhunter.agent.scoring.Whitelist;
import com.memhunter.agent.scoring.baseline.BaselineIndex;
import com.memhunter.agent.scoring.baseline.BaselineLoader;
import com.memhunter.agent.util.ReflectUtil;
import com.memhunter.agent.verify.VerifyExecutor;

import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class MemHunterAgent {

    public static void agentmain(String agentArgs, Instrumentation inst) {
        try {
            AgentArgs args = AgentArgs.parse(agentArgs);
            if (!"scan".equals(args.command)) {
                ScanReport locatingReport = new ScanReport();
                TomcatScanner tomcat = new TomcatScanner();
                List<Object> tomcatContexts = tomcat.locateContexts(inst, locatingReport);
                if (!dispatchNonScan(args, tomcatContexts)) {
                    System.err.println("[memhunter] unsupported command: " + args.command);
                }
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

            BaselineIndex baselineIndex = BaselineIndex.empty();
            String baselineFile = args.options.get("baseline");
            if (baselineFile != null) {
                baselineIndex = BaselineLoader.load(baselineFile);
                if (baselineIndex.isEmpty()) {
                    report.partialErrors.add(new ScanReport.PartialError(
                            "BaselineLoader", "failed to load or empty baseline: " + baselineFile));
                }
            }

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
            new RuleEngine().evaluate(all, new ScanContext(appCtx, whitelist, explain, baselineIndex));

            report.findings = all;
            populateSummary(report, all, baselineIndex);

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

    static boolean dispatchNonScanForTest(AgentArgs args, List<?> tomcatContexts) throws Exception {
        return dispatchNonScan(args, tomcatContexts);
    }

    private static boolean dispatchNonScan(AgentArgs args, List<?> tomcatContexts) throws Exception {
        if ("verify".equals(args.command)) {
            String id = args.options.get("id");
            VerifyExecutor.VerifyResult result = new VerifyExecutor(requireFirstContext(tomcatContexts))
                    .verify(id, evidenceDir(args));
            System.out.println("[memhunter] verify finished, id=" + id
                    + ", stillPresent=" + result.stillPresent);
            return true;
        }
        if ("clean".equals(args.command) && args.options.containsKey("dry-run")) {
            Object ctx = requireFirstContext(tomcatContexts);
            String id = args.options.get("id");
            Path evidenceDir = evidenceDir(args);
            Finding finding = findTomcatFilter(ctx, id);
            if (finding == null) {
                throw new IllegalStateException("finding not located: " + id);
            }
            TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
            CleanPlan plan = cleaner.plan(finding, false);
            if (plan == null) {
                throw new IllegalStateException("clean plan could not be generated: " + id);
            }
            plan.evidenceDir = evidenceDir.toString();
            plan.planFile = evidenceDir.resolve("evidence").resolve(id).resolve("clean-plan.json").toString();
            new EvidenceWriter(evidenceDir).writeBundle(finding, plan, beforeSnapshot(finding), null);
            System.out.println("[memhunter] clean dry-run finished, id=" + id
                    + ", plan=" + plan.planFile);
            return true;
        }
        if ("clean".equals(args.command) && args.options.containsKey("confirm")) {
            Object ctx = requireFirstContext(tomcatContexts);
            String id = args.options.get("id");
            Path evidenceDir = evidenceDir(args);
            Path planFile = evidenceDir.resolve("evidence").resolve(id).resolve("clean-plan.json");
            CleanPlan persistedPlan = CleanPlanReader.read(planFile);
            Finding finding = findTomcatFilter(ctx, id);
            if (finding == null) {
                throw new IllegalStateException("finding not located: " + id);
            }
            TomcatFilterCleaner cleaner = new TomcatFilterCleaner(ctx);
            CleanPlan freshPlan = cleaner.plan(finding, args.options.containsKey("force"));
            if (freshPlan == null) {
                throw new IllegalStateException("clean plan could not be regenerated: " + id);
            }
            freshPlan.evidenceDir = persistedPlan.evidenceDir;
            freshPlan.planFile = persistedPlan.planFile;
            CleanResult result = cleaner.execute(freshPlan, args.options.containsKey("force"));
            new EvidenceWriter(evidenceDir).writeResult(id, result);
            System.out.println("[memhunter] clean confirm finished, id=" + id
                    + ", success=" + result.success);
            return true;
        }
        return false;
    }

    private static Object firstContext(List<?> tomcatContexts) {
        if (tomcatContexts == null || tomcatContexts.isEmpty()) return null;
        return tomcatContexts.get(0);
    }

    private static Object requireFirstContext(List<?> tomcatContexts) {
        Object ctx = firstContext(tomcatContexts);
        if (ctx == null) {
            throw new IllegalStateException("no Tomcat context located");
        }
        return ctx;
    }

    private static Path evidenceDir(AgentArgs args) {
        return Paths.get(args.options.getOrDefault("evidence-dir", "."));
    }

    private static Finding findTomcatFilter(Object ctx, String id) {
        List<Finding> findings = new com.memhunter.agent.scanner.tomcat.TomcatFilterScanner(ctx)
                .scan(new ScanReport());
        new RuleEngine().evaluate(findings,
                new ScanContext(null, Whitelist.defaults(), false, BaselineIndex.empty()));
        for (Finding f : findings) {
            if (f != null && id != null && id.equals(f.id)) {
                return f;
            }
        }
        return null;
    }

    private static Map<String, Object> beforeSnapshot(Finding finding) {
        Map<String, Object> snapshot = new HashMap<>();
        snapshot.put("findingId", finding.id);
        snapshot.put("type", finding.type);
        snapshot.put("name", finding.name);
        snapshot.put("className", finding.className);
        snapshot.put("attributes", finding.attributes);
        return snapshot;
    }

    static void populateSummary(ScanReport report, List<Finding> findings, BaselineIndex baselineIndex) {
        if (report == null || findings == null) return;
        BaselineIndex effectiveBaseline = baselineIndex != null ? baselineIndex : BaselineIndex.empty();
        report.summary.totalFindings = findings.size();
        for (Finding f : findings) {
            if ("critical".equals(f.level)) report.summary.critical++;
            else if ("high".equals(f.level)) report.summary.high++;
            else if ("suspicious".equals(f.level)) report.summary.suspicious++;
            else report.summary.low++;

            if (f.id != null && !effectiveBaseline.isEmpty()) {
                if (effectiveBaseline.contains(f.id)) {
                    report.summary.baselineMatchedCount++;
                } else {
                    report.summary.baselineNewCount++;
                }
            }
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
