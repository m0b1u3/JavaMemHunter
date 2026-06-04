**English** | [中文](README.zh-CN.md)

# JavaMemHunter

> Detect, score, clean, and verify Java memory-resident webshells in
> Tomcat / Spring Boot applications — at runtime, via Java Agent attach.

[![Test](https://github.com/m0b1u3/JavaMemHunter/actions/workflows/test.yml/badge.svg)](https://github.com/m0b1u3/JavaMemHunter/actions/workflows/test.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## What

JavaMemHunter attaches to a running JVM and finds six categories of
in-memory webshell:

| Category           | Description                                                       |
|--------------------|-------------------------------------------------------------------|
| tomcat-filter      | Filter injected into `StandardContext.filterConfigs`              |
| tomcat-servlet     | Servlet wrapped as a `StandardWrapper`                            |
| tomcat-listener    | `ServletContextListener` / request listener                       |
| tomcat-valve       | `StandardContextValve` replaced                                   |
| spring-interceptor | `HandlerInterceptor` injected into `AbstractHandlerMapping`       |
| spring-mapping     | Malicious mapping registered with `RequestMappingHandlerMapping`  |

Each finding is scored by a rule engine (RMI / `Runtime.exec` / Process
spawn / crypto / bytecode anomalies / baseline-new). High-score
findings can be cleaned via a 5-phase atomic plan (scan -> backup ->
replace -> destroy -> verify), with a JSON evidence bundle suitable for
IR review and rollback metadata.

## Why

Static scanners miss in-memory shells. Existing dynamic tools detect
but rarely clean — and never with rollback or evidence trail.
JavaMemHunter gives blue teams a way to remove a live shell with a
JSON evidence bundle and (where applicable) restore the previous
state if the cleanup mis-fires.

## Quick start

```bash
# 1. Build
./mvnw -DskipTests package

# 2. Find the target PID
jps -l

# 3. Scan
java -jar attach/target/memhunter-attach.jar <pid> agent/target/memhunter-agent.jar scan --output scan.json
# --output is optional: without it the report is written to memhunter-scan-<timestamp>.json in the
# current directory. Either way a concise summary (critical/high/suspicious findings + a count of
# suppressed low ones) is printed to your terminal and the full report path is shown.
# Each listed finding is annotated with its access path where applicable: path=[/*] for a filter,
# path=[/foo] for a servlet mapping, the injected URI for a Behinder agent shell, etc. Event- or
# pipeline-triggered shells with no URL (listeners, valves) show trigger=/pipeline= instead.
# Note: the report path must not contain spaces (agent argument parsing splits on whitespace).

# 4. Dry-run clean (writes plan, makes no change)
java -jar attach/target/memhunter-attach.jar <pid> agent/target/memhunter-agent.jar \
     clean --id F-xxx --dry-run --evidence-dir .

# 5. Confirm clean (prompts for "yes")
java -jar attach/target/memhunter-attach.jar <pid> agent/target/memhunter-agent.jar \
     clean --id F-xxx --confirm --evidence-dir .
```

## Supported environments

| Component   | Versions verified                                                 |
|-------------|-------------------------------------------------------------------|
| JDK         | 17 (CI); 8 manual on Windows (NIO selector workaround)            |
| Tomcat      | 9.x (via Spring Boot 2.7), 10.x (via Spring Boot 3.2)             |
| Spring Boot | 2.7.x, 3.2.x                                                      |
| OS          | Linux (CI), Windows 11 (manual)                                   |

## Known limitations

- **JDK 17+ requires `--add-opens` on the target JVM.** The agent
  walks Thread/field graphs reflectively to locate Tomcat
  `StandardEngine`. JDK 9 module encapsulation blocks this unless you
  start the target with:

  ```
  java --add-opens=java.base/java.lang=ALL-UNNAMED \
       --add-opens=java.base/java.lang.reflect=ALL-UNNAMED \
       --add-opens=java.base/java.util=ALL-UNNAMED \
       --add-opens=java.base/java.util.concurrent=ALL-UNNAMED \
       -jar your-app.jar
  ```

  Without these flags the scanner falls back to a less precise
  class-loaded mode (`class-filter` / `class-servlet` etc.) and the
  cleaner cannot operate. JDK 8 has no module system and needs no
  flags.
- **Windows + JDK 17 NIO Selector bug** — use JDK 8 to run the target
  JVM, or run the target on Linux.
- **Standalone Tomcat (non-embedded) not in CI** — likely works but
  unverified; please open an issue if you hit problems.
- **Spring Boot 1.x, Tomcat 7 / 8.5, Tomcat 11** — not in the test
  matrix.
- **Spring Bean cleaning** — out of scope (rollback complexity too
  high to be safe).

## Documentation

- [中文详细文档 (full Chinese docs)](README.zh-CN.md)
- [Design notes (Chinese)](java_memshell_scanner_design.md)
- [Contributing](CONTRIBUTING.md)
- [Version history](README.zh-CN.md#版本演进)

## License

Apache License 2.0 — see [LICENSE](LICENSE).
