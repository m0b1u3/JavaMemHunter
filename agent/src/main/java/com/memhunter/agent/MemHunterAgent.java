package com.memhunter.agent;

import com.memhunter.agent.cleaner.CleanPlanReader;
import com.memhunter.agent.cleaner.Cleaner;
import com.memhunter.agent.cleaner.CleanerRegistry;
import com.memhunter.agent.cleaner.EvidenceWriter;
import com.memhunter.agent.cleaner.PlanReconciler;
import com.memhunter.agent.cleaner.PlanStaleException;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class MemHunterAgent {

    public static final int EXIT_OK = 0;
    public static final int EXIT_EXECUTE_FAILED = 2;
    public static final int EXIT_PLAN_STALE = 3;

    private static final CleanerRegistry CLEANER_REGISTRY = CleanerRegistry.defaultRegistry();

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

            // 4. Agent-type memshell scan (v0.10); v0.11 passes evidence-dir for bytecode dumps
            all.addAll(new com.memhunter.agent.scanner.agent.AgentTypeScanner()
                    .scan(inst, report, args.options.get("evidence-dir")));

            // 5. v0.3 scoring
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
            Object ctx = requireFirstContext(tomcatContexts);
            Object springCtx = locateApplicationContext(ctx);
            VerifyExecutor.VerifyResult result = new VerifyExecutor(ctx, springCtx)
                    .verify(id, evidenceDir(args));
            System.out.println("[memhunter] verify finished, id=" + id
                    + ", stillPresent=" + result.stillPresent);
            return true;
        }
        if ("clean".equals(args.command) && args.options.containsKey("dry-run")) {
            Object ctx = requireFirstContext(tomcatContexts);
            Object springCtx = locateApplicationContext(ctx);
            String id = args.options.get("id");
            Path evidenceDir = evidenceDir(args);
            Finding finding = FindingLocator.find(ctx, springCtx, id);
            if (finding == null) {
                throw new IllegalStateException("finding not located: " + id);
            }
            Cleaner cleaner = CLEANER_REGISTRY.resolve(finding.type, ctx, springCtx);
            if (cleaner == null) {
                throw new IllegalStateException(
                    "no cleaner available for type: " + finding.type + " (context not located)");
            }
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
            int exit = dispatchCleanConfirm(ctx, args);
            if (exit == EXIT_PLAN_STALE) {
                System.out.println("[memhunter] clean confirm rejected: plan stale, id="
                        + args.options.get("id"));
            } else {
                System.out.println("[memhunter] clean confirm finished, id="
                        + args.options.get("id") + ", exit=" + exit);
            }
            return true;
        }
        return false;
    }

    /**
     * Visible-for-testing seam: drives the clean --confirm dispatch with a
     * pre-resolved StandardContext, returning an exit code instead of System.exit.
     * Shares the {@link #dispatchCleanConfirm} helper with the production path —
     * no logic fork.
     */
    static int dispatchForTest(Object standardContext, AgentArgs args) throws Exception {
        return dispatchForTest(standardContext, null, args);
    }

    static int dispatchForTest(Object tomcatCtx, Object springCtx, AgentArgs args) throws Exception {
        if (!"clean".equals(args.command) || !args.options.containsKey("confirm")) {
            throw new IllegalArgumentException(
                    "dispatchForTest only handles `clean --confirm`, got: " + args.command);
        }
        return dispatchCleanConfirm(tomcatCtx, springCtx, args);
    }

    private static int dispatchCleanConfirm(Object ctx, AgentArgs args) throws Exception {
        return dispatchCleanConfirm(ctx, locateApplicationContext(ctx), args);
    }

    private static int dispatchCleanConfirm(Object ctx, Object springCtx, AgentArgs args) throws Exception {
        String id = args.options.get("id");
        boolean confirmForceFlag = args.options.containsKey("force");
        Path evidenceDir = evidenceDir(args);
        Path planFile = evidenceDir.resolve("evidence").resolve(id).resolve("clean-plan.json");
        CleanPlan persistedPlan = CleanPlanReader.read(planFile);

        Finding finding = FindingLocator.find(ctx, springCtx, id);
        if (finding == null) {
            throw new IllegalStateException("finding not located: " + id);
        }
        Cleaner cleaner = CLEANER_REGISTRY.resolve(finding.type, ctx, springCtx);
        if (cleaner == null) {
            CleanResult unsupported = new CleanResult();
            unsupported.findingId = id;
            unsupported.success = false;
            unsupported.rolledBack = false;
            unsupported.verifiedDisappeared = false;
            unsupported.executedSteps = Arrays.asList(
                    "pre-execute: no cleaner available for type " + finding.type);
            unsupported.failureReason = "no cleaner available for type: " + finding.type
                    + " (context not located)";
            unsupported.executedAt = System.currentTimeMillis();
            new EvidenceWriter(evidenceDir).writeResult(id, unsupported);
            return EXIT_EXECUTE_FAILED;
        }
        CleanPlan freshPlan = cleaner.plan(finding, confirmForceFlag);
        if (freshPlan == null) {
            throw new IllegalStateException("clean plan could not be regenerated: " + id);
        }
        freshPlan.evidenceDir = persistedPlan.evidenceDir;
        freshPlan.planFile = persistedPlan.planFile;

        // v0.6.1: reconcile persisted vs fresh plan + confirm-time --force flag
        try {
            PlanReconciler.requireConsistent(persistedPlan, freshPlan, confirmForceFlag);
        } catch (PlanStaleException e) {
            CleanResult stale = new CleanResult();
            stale.findingId = persistedPlan.findingId;
            stale.success = false;
            stale.rolledBack = false;
            stale.verifiedDisappeared = false;
            stale.executedSteps = Arrays.asList(
                    "pre-execute: plan staleness check FAILED — refusing to clean");
            stale.failureReason = e.getMessage();
            stale.executedAt = System.currentTimeMillis();
            new EvidenceWriter(evidenceDir).writeResult(persistedPlan.findingId, stale);
            return EXIT_PLAN_STALE;
        }

        CleanResult result = cleaner.execute(freshPlan, confirmForceFlag);
        new EvidenceWriter(evidenceDir).writeResult(id, result);
        return result.success ? EXIT_OK : EXIT_EXECUTE_FAILED;
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

    private static Object locateApplicationContext(Object tomcatCtx) {
        try {
            java.util.List<Object> tomcatContexts = new java.util.ArrayList<>();
            if (tomcatCtx != null) tomcatContexts.add(tomcatCtx);
            java.util.List<Object> servletInstances = extractServletInstances(tomcatContexts);
            com.memhunter.agent.model.ScanReport report = new com.memhunter.agent.model.ScanReport();
            java.util.List<Object> appCtxs = new com.memhunter.agent.scanner.spring.SpringScanner()
                .locateContexts(tomcatContexts, servletInstances, report);
            return appCtxs.isEmpty() ? null : appCtxs.get(0);
        } catch (Throwable t) {
            return null;
        }
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
