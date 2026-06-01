# v0.8 Clean Flow E2E Evidence

This directory archives the end-to-end clean-flow evidence for v0.8 — covering
the two new Spring cleaners (`spring-mapping` and `spring-interceptor`) plus a
regression sweep of the four Tomcat cleaners (`tomcat-filter`,
`tomcat-servlet`, `tomcat-listener-*`, `tomcat-valve`) under the new dual-context
dispatch (`MemHunterAgent.findFindingById` + `CleanerRegistry.resolve(type,
tomcatCtx, springCtx)`).

## Layout

```text
v0.8-clean-flow-evidence/
├── README.md                       (this file)
├── v0.8-before.json                (scan output BEFORE clean — 6 findings expected)
├── v0.8-after.json                 (scan output AFTER all 6 clean cycles — findings gone)
└── evidence/
    ├── finding-spring-mapping-<hash>/
    │   ├── finding.json
    │   ├── clean-plan.json
    │   ├── before-snapshot.json
    │   ├── clean-result.json       (success=true, verifiedDisappeared=true)
    │   └── verify-result.json      (stillPresent=false)
    ├── finding-spring-interceptor-<hash>/...
    ├── finding-tomcat-filter-<hash>/...
    ├── finding-tomcat-servlet-<hash>/...
    ├── finding-tomcat-listener-request-<hash>/...
    └── finding-tomcat-valve-<hash>/...
```

## How this was reproduced

```bash
# 1. Build everything
./mvnw package -DskipTests

# 2. Launch test-target (Spring Boot embedded Tomcat 9)
java -Djava.net.preferIPv4Stack=true -jar test-target/target/memhunter-test-target.jar &
# Wait for "Started TestTargetApplication" log line.

# 3. Inject 6 mem-shells via the test endpoints
curl http://localhost:8080/inject/filter
curl http://localhost:8080/inject/servlet
curl http://localhost:8080/inject/listener
curl http://localhost:8080/inject/valve
curl http://localhost:8080/inject/spring-mapping
curl http://localhost:8080/inject/spring-interceptor

# 4. Find the PID
PID=$(java -jar attach/target/memhunter-attach.jar list | grep memhunter-test-target | awk '{print $1}')

# 5. BEFORE snapshot
java -jar attach/target/memhunter-attach.jar $PID \
    agent/target/memhunter-agent.jar scan \
    --output docs/superpowers/specs/v0.8-clean-flow-evidence/v0.8-before.json

# 6. For each of the 6 finding IDs (read from v0.8-before.json):
#    Run dry-run, then echo yes | confirm, then verify.
for FID in <fid-filter> <fid-servlet> <fid-listener> <fid-valve> <fid-spring-mapping> <fid-spring-interceptor>; do
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

# 7. AFTER snapshot
java -jar attach/target/memhunter-attach.jar $PID \
    agent/target/memhunter-agent.jar scan \
    --output docs/superpowers/specs/v0.8-clean-flow-evidence/v0.8-after.json

# 8. Sanity check: hit a normal endpoint to confirm the app still works
curl http://localhost:8080/

# 9. Stop test-target
kill $!
```

## Expected outcome

- `v0.8-before.json` contains 6 critical findings (the injected mem-shells)
- All 6 `clean-result.json` show `success: true, verifiedDisappeared: true`
- All 6 `verify-result.json` show `stillPresent: false`
- `v0.8-after.json` shows ZERO of the 6 findings (the runtime is clean)
- HTTP requests to the test-target continue to succeed after cleaning
  (the legit Spring routes survive; only the injected ones are gone)

## What's new vs v0.7.1 evidence

| Finding type | v0.7.1 evidence | v0.8 evidence |
|---|---|---|
| `tomcat-filter` | ✅ | ✅ regression-checked under new dispatch |
| `tomcat-servlet` | ✅ | ✅ regression-checked |
| `tomcat-listener-request` | ✅ | ✅ regression-checked |
| `tomcat-valve` | ✅ | ✅ regression-checked |
| `spring-mapping` | — | ✅ **new in v0.8** (official `unregisterMapping`) |
| `spring-interceptor` | — | ✅ **new in v0.8** (atomic `adaptedInterceptors` copy-replace) |
