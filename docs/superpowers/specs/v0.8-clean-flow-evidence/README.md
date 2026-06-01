# v0.8 Clean Flow E2E Evidence

End-to-end clean-flow evidence captured against a real Spring Boot 2.7 +
Tomcat 9.0.83 test-target running on JDK 8. Covers all six runtime finding
types — four Tomcat (regression of v0.7) plus the two new Spring cleaners
shipped in v0.8 (`spring-mapping` + `spring-interceptor`).

## Result summary

| Finding ID | Type | Score | Phase A→E result |
|---|---|---|---|
| `finding-tomcat-filter-518041b8` | `tomcat-filter` (FakeFilter) | 21 | ✅ success / verifiedDisappeared=true |
| `finding-tomcat-servlet-0334f00b` | `tomcat-servlet` (FakeServlet) | 17 | ✅ success / verifiedDisappeared=true |
| `finding-tomcat-listener-request-41c52339` | `tomcat-listener-request` (FakeListener) | 19 | ✅ success / verifiedDisappeared=true |
| `finding-tomcat-valve-26222546` | `tomcat-valve` ($Proxy58 / FakeValve) | 14 | ✅ success / verifiedDisappeared=true |
| `finding-spring-interceptor-fac4e2b6` | `spring-interceptor` (FakeInterceptor) | 19 | ✅ success / verifiedDisappeared=true |
| `finding-spring-mapping-010fa957` | `spring-mapping` (FakeSpringController `/spring-fake`) | 6 | ⚠️ cleaned (verify=stillPresent=false) but **no evidence bundle** — see "force gate gap" below |

The test-target's legitimate `/hello` endpoint continued to respond `200 hello
from test target` after all six clean cycles, confirming the cleans did not
break unrelated routes.

## Layout

```text
v0.8-clean-flow-evidence/
├── README.md                       (this file)
├── v0.8-before.json                (scan output after 6 injections; 71 findings)
├── v0.8-after.json                 (scan output after 6 clean cycles; 66 findings — runtime mem-shells gone)
└── evidence/
    ├── finding-tomcat-filter-518041b8/         {finding,clean-plan,before-snapshot,clean-result,verify-result}.json
    ├── finding-tomcat-servlet-0334f00b/        {full bundle}
    ├── finding-tomcat-listener-request-41c52339/ {full bundle}
    ├── finding-tomcat-valve-26222546/          {full bundle}
    ├── finding-spring-interceptor-fac4e2b6/    {full bundle}
    └── finding-spring-mapping-010fa957/        verify-result.json only — see "force gate gap"
```

## Force gate gap (discovered during this E2E)

`finding-spring-mapping-010fa957` (the injected `FakeSpringController @ /spring-fake`)
scored only **6** because the injector class lives in the project's own
`com.memhunter.testinjector.*` package and only triggered three scoring rules
(`implements-web-component +3`, `high-entropy-class-name +1`,
`non-business-package +2`). The 6-rule threshold for unforced clean is `>=7`,
so it would normally need `--force`.

Running `clean --id <fid> --dry-run --force` fails with:

```
[memhunter] agent failed: --force must be used with --confirm
java.lang.IllegalArgumentException: --force must be used with --confirm
    at com.memhunter.agent.AgentArgs.validate(AgentArgs.java:74)
```

This is the v0.6 Task 2 mutual-exclusion rule. The rule's original intent was
to prevent accidentally setting `--force` without `--confirm` (you should
ALWAYS dry-run before forcing). But the rule blocks the *legitimate* dry-run
phase of a forced clean, leaving no way to capture an evidence bundle for
sub-threshold findings.

**Observed runtime behavior in this E2E**: `clean --id <fid> --confirm --force`
*succeeded* (the mapping was unregistered and `verify` reports
`stillPresent=false`) even with no persisted `clean-plan.json` to reconcile
against. This means the v0.6.1 audit-chain check (PlanReconciler) is also
silently bypassed when the plan file does not exist. The cleaner went straight
through Phase A→E using the fresh re-scan, with no prior plan to compare.

**This is a v0.8.x patch candidate** — track in the issue list:

1. **Force-gate accessibility** — allow `clean --dry-run --force` so operators
   can produce an evidence bundle for sub-threshold findings before confirming.
2. **PlanReconciler missing-plan strictness** — when `clean --confirm` is
   invoked and the persisted plan file is absent, the dispatch should refuse
   with `EXIT_PLAN_STALE` (or a new `EXIT_PLAN_MISSING`) rather than silently
   proceeding. Otherwise the audit chain has a back door.

Both are out of scope for v0.8.1 (which is purely E2E archiving) and are
queued for a separate v0.8.2 patch with TDD coverage.

## How this was reproduced

```bash
# Build (project root)
./mvnw clean package -DskipTests

# Launch test-target on JDK 8 (avoids the JDK 17 + Windows 11 NIO Selector bug)
java8 -jar test-target/target/memhunter-test-target.jar

# Inject the six mem-shells in any order (valve last is safest; see fix in
# commit 7e76032 for the JDK 17 IllegalAccessException workaround inside
# FakeValveInjector).
curl http://localhost:8080/inject/filter
curl http://localhost:8080/inject/servlet
curl http://localhost:8080/inject/listener
curl http://localhost:8080/inject/spring-mapping
curl http://localhost:8080/inject/spring-interceptor
curl http://localhost:8080/inject/valve

# Find PID
PID=$(jps -l | grep memhunter-test-target | awk '{print $1}')

# BEFORE snapshot
java -jar attach/target/memhunter-attach.jar $PID \
    agent/target/memhunter-agent.jar scan \
    --output docs/superpowers/specs/v0.8-clean-flow-evidence/v0.8-before.json

# Read finding IDs from v0.8-before.json for the six runtime types above.

# For each finding: dry-run → confirm (pipe "yes") → verify
for FID in <6-finding-ids>; do
    java -jar attach/target/memhunter-attach.jar $PID \
        agent/target/memhunter-agent.jar clean --id $FID --dry-run \
        --evidence-dir docs/superpowers/specs/v0.8-clean-flow-evidence
    echo yes | java -jar attach/target/memhunter-attach.jar $PID \
        agent/target/memhunter-agent.jar clean --id $FID --confirm \
        --evidence-dir docs/superpowers/specs/v0.8-clean-flow-evidence
    java -jar attach/target/memhunter-attach.jar $PID \
        agent/target/memhunter-agent.jar verify --id $FID \
        --evidence-dir docs/superpowers/specs/v0.8-clean-flow-evidence
done

# AFTER snapshot
java -jar attach/target/memhunter-attach.jar $PID \
    agent/target/memhunter-agent.jar scan \
    --output docs/superpowers/specs/v0.8-clean-flow-evidence/v0.8-after.json

# Sanity: legit route still works
curl http://localhost:8080/hello   # → "hello from test target"
```

## What's new vs v0.7.1 evidence

| Finding type | v0.7.1 evidence | v0.8 evidence |
|---|---|---|
| `tomcat-filter` | ✅ | ✅ regression-checked under new dispatch (no behavior change vs v0.7.1) |
| `tomcat-servlet` | ✅ | ✅ regression-checked |
| `tomcat-listener-request` | ✅ | ✅ regression-checked |
| `tomcat-valve` | ✅ | ✅ regression-checked (with `FakeValveInjector` JDK 17 setAccessible fix; commit `7e76032`) |
| `spring-interceptor` | — | ✅ **new in v0.8** — atomic `adaptedInterceptors` copy-replace across all mapping beans |
| `spring-mapping` | — | ⚠️ **new in v0.8** — official `unregisterMapping(info)` works; evidence bundle blocked by force-gate gap (see above) |
