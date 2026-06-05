**English** | [中文](README.zh-CN.md)

# JavaMemHunter

> Detect, score, clean, and verify Java memory-resident webshells in
> Tomcat / Spring Boot applications — at runtime, via Java Agent attach.

[![Test](https://github.com/m0b1u3/JavaMemHunter/actions/workflows/test.yml/badge.svg)](https://github.com/m0b1u3/JavaMemHunter/actions/workflows/test.yml)
[![Release](https://img.shields.io/badge/release-v1.0-blue.svg)](https://github.com/m0b1u3/JavaMemHunter/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![JDK](https://img.shields.io/badge/JDK-8%2B-orange.svg)](#supported-environments)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

JavaMemHunter attaches to a **running JVM**, finds in-memory and file-based webshells,
prints a concise terminal summary with each shell's access path, and can clean a
confirmed shell atomically with a rollback-ready JSON evidence bundle.

## What it catches

Organised by the shell you're hunting (validated against live samples):

| Shell                         | How it hides                                                        | How JavaMemHunter finds it                              |
|-------------------------------|---------------------------------------------------------------------|---------------------------------------------------------|
| **Behinder (冰蝎) agent shell** | `redefineClasses` tampers `HttpServlet.service` bytecode            | bytecode-tamper diff vs disk jar; extracts injected URI/decrypt-class |
| **Godzilla (哥斯拉) filter shell** | Jackson classes renamed into `org.apache.coyote.*`, dynamically defined | masqueraded-package detection (framework name + no jar source) |
| **JSP webshell**              | a `.jsp` file on disk, compiled to `org.apache.jsp.*`               | class-name reverse-mapping to the `.jsp` access URL     |
| **Tomcat Filter / Servlet / Listener / Valve** | registered at runtime into the container, no class file | container-registry scan + runtime-only / wildcard heuristics |
| **Spring Interceptor / Mapping** | injected into `AbstractHandlerMapping` / `RequestMappingHandlerMapping` | Spring runtime scan                                |

## How it works

- **Container-registry scan** — walks Tomcat `StandardContext` filter/servlet/listener/valve
  registries and Spring handler mappings to find *registered* components.
- **Class-loaded scan** — `ClassScanner` walks every loaded class for web components the
  container view might miss (file-based JSP shells, dependency classes).
- **Agent-type detection** — `AgentTypeScanner` compares in-memory bytecode of key classes
  (`HttpServlet.service`, valves, dispatchers) against their disk jars via ASM method-body
  fingerprints, catching `redefineClasses`-based shells (Behinder); extracts the injected
  access path / decrypt-class strings from the tampered constant pool.
- **Rule-engine scoring** — independent rules sum to a score → `critical` / `high` /
  `suspicious` / `low`. Highlights: `masqueraded-package` (framework name + null codeSource),
  bytecode-malice checks (`Runtime.exec` / `defineClass` / `Cipher.doFinal`), and several
  false-positive suppressors.
- **Noise control, validated to zero false positives on a live target**:
  benign webapp components are not reported; JVM reflection-generated classes are whitelisted;
  same-class findings from different scanners are deduplicated; a Godzilla filter shell's
  injected Jackson *dependency* classes are downgraded out of `critical` (still reported in
  `high`).
- **Access-path annotation** — every listed finding shows where to find it: a filter's
  `urlPatterns`, a servlet's mappings, a JSP's reverse-mapped `.jsp` URL, or a Behinder agent
  shell's injected URI.
- **Atomic clean + verify** — a 5-phase plan (rescan → backup → replace → destroy → verify)
  with a JSON evidence bundle and rollback metadata.

## Clean capability

| Finding type | Scan | Clean | How                                                       |
|--------------|------|-------|-----------------------------------------------------------|
| `tomcat-filter` | ✅ | ✅ | atomic copy-replace of filterDefs / filterMaps / filterConfigs |
| `tomcat-servlet` | ✅ | ✅ | atomic copy-replace of children / servletMappings        |
| `tomcat-listener-{request,session,context,other}` | ✅ | ✅ | copy-replace of application(Event/Lifecycle)Listeners |
| `tomcat-valve` | ✅ | ✅ | relink the Pipeline chain                                 |
| `spring-mapping` | ✅ | ✅ | official `unregisterMapping(info)`                        |
| `spring-interceptor` | ✅ | ✅ | copy-replace `adaptedInterceptors` across beans          |
| `agent-bytecode-tampered` (Behinder) | ✅ | — | bytecode-tampered; restart / manual remediation           |
| `class-*` (JVM class level) | ✅ | — | scoring only; a JSP webshell is a `.jsp` file to delete from disk |

All cleaning is: dry-run (writes plan + evidence) → exact lowercase `yes` confirm on the attach
side → confirm (atomic replace + verify + rollback on failure) → verify (independent rescan).

## Quick start

```bash
# 1. Build
./mvnw -DskipTests package

# 2. Find the target PID
jps -l

# 3. Scan (--output is optional; defaults to ./memhunter-scan-<timestamp>.json)
java -jar attach/target/memhunter-attach.jar <pid> agent/target/memhunter-agent.jar scan
```

A concise summary is printed straight to your terminal — only `critical` / `high` /
`suspicious` are listed, `low` is counted but not shown:

```
[memhunter] scan summary (PID <pid>):
  critical: 4  high: 9  suspicious: 0  low: 67
  [critical] tomcat-filter  org.apache.coyote.JavaType                     score=16  path=[/*]
  [critical] tomcat-filter  org.apache.coyote.MapperFeature                score=16  path=[/*]
  [critical] tomcat-filter  org.apache.coyote.jsontype.impl.TypeSerializerBase  score=16  path=[/*]
  [critical] tomcat-filter  org.apache.coyote.deser.BeanDeserializerModifier    score=16  path=[/*]
  [high] class-servlet  org.apache.coyote.util.EnumValues   score=8         (Jackson dependency class, downgraded)
  [high] class-servlet  org.apache.jsp.<obfuscated>_jsp     score=7  path=[/<obfuscated>.jsp]
  [high] tomcat-servlet  <null>  score=8  path=[/<shell-path>]
[memhunter] full report: ./memhunter-scan-<timestamp>.json
```

```bash
# 4. Dry-run clean (writes a plan, makes no change)
java -jar attach/target/memhunter-attach.jar <pid> agent/target/memhunter-agent.jar \
     clean --id <findingId> --dry-run --evidence-dir .

# 5. Confirm clean (prompts for an exact "yes")
java -jar attach/target/memhunter-attach.jar <pid> agent/target/memhunter-agent.jar \
     clean --id <findingId> --confirm --evidence-dir .
```

> Note: the report path must not contain spaces — agent argument parsing splits on whitespace.

## Reading the output

**Levels** — `critical` = an activated, registered shell (act now); `high` = a webshell,
a `null`-class servlet shell, or an injected dependency class (review); `suspicious` = weaker
signals; `low` = background noise (benign components, JVM classes), counted only.

**The path/location after each finding:**

- `path=[...]` — an **access path** you can block at the WAF / search in access logs:
  a filter's `/*`, a servlet's mapping, a JSP's `.jsp` URL, or a Behinder agent shell's URI.
- `trigger=` / `pipeline=` — an event- or pipeline-triggered shell (listener / valve) with
  **no URL**; it fires on any request, so there's no single path to block.
- A JSP `path=[/foo.jsp]` points at a **file to delete from disk** — JSP webshells are
  file-based, not in-memory.

The full JSON report keeps **every** finding (including `low`) for forensics; the terminal
summary is the triage view.

## CLI options

| Option | Command | Meaning |
|--------|---------|---------|
| `--output <file>` | scan | report path (optional; defaults to `./memhunter-scan-<timestamp>.json`). Either way the terminal summary is printed and the full report path shown. Path must not contain spaces. |
| `--baseline <file>` | scan | a previous ScanReport JSON; findings not in the baseline get `baseline-new` (+4) |
| `--whitelist <file>` | scan | user whitelist, one `<type>:<value>` per line, `<type>` ∈ {framework, business, agent, codesource} |
| `--explain` | scan | include per-rule `ruleHits` in each finding |
| `--id <findingId>` | clean / verify | target finding ID (from the scan report) |
| `--dry-run` | clean | write `clean-plan.json` + evidence, make no runtime change |
| `--confirm` | clean | read the dry-run plan, execute after `yes` on stdin |
| `--force` | clean | skip the score < 7 gate; persisted and confirm flags must agree |
| `--evidence-dir <dir>` | clean / verify | evidence directory root (default: current dir) |

### Whitelist file example

```text
business:com.mycompany.app.
framework:com.acme.shared.
agent:com.custom.tracer
codesource:/opt/myapp/
```

### Clean evidence directory layout

```text
<evidence-dir>/evidence/<findingId>/
├── finding.json           # the original Finding (score / level / reasons)
├── clean-plan.json        # written by dry-run; 4 fields strictly checked at confirm
├── before-snapshot.json   # reflective snapshot of the Tomcat/Spring internals
├── clean-result.json      # written after confirm (success / rolledBack / verifiedDisappeared / executedSteps)
└── verify-result.json     # written by the independent verify command
```

## Supported environments

| Component   | Versions verified                                                       |
|-------------|-------------------------------------------------------------------------|
| JDK         | target JVM 8 / 11 / 17 / 21 (agent is JDK 8 bytecode); JDK 17 needs `--add-opens` (below) |
| Tomcat      | 9.x (incl. 9.0.94 standalone, manual), 10.x (via Spring Boot 3.2)       |
| Spring Boot | 2.7.x, 3.2.x                                                            |
| OS          | Linux (CI), Windows 11 (manual)                                         |
| Shells      | Behinder agent shell, Godzilla filter shell, JSP webshell (live, manual)|

## Known limitations

- **JDK 17+ requires `--add-opens` on the target JVM.** The agent walks Thread/field graphs
  reflectively to locate the Tomcat `StandardEngine`. JDK 9 module encapsulation blocks this
  unless the target starts with:

  ```
  java --add-opens=java.base/java.lang=ALL-UNNAMED \
       --add-opens=java.base/java.lang.reflect=ALL-UNNAMED \
       --add-opens=java.base/java.util=ALL-UNNAMED \
       --add-opens=java.base/java.util.concurrent=ALL-UNNAMED \
       -jar your-app.jar
  ```

  Without these flags the scanner falls back to a less precise class-loaded mode and the
  cleaner cannot operate. JDK 8 has no module system and needs no flags.
- **`--output` paths must not contain spaces** — the attach→agent argument pipeline splits on
  whitespace; a path with spaces is rejected with a clear error.
- **antiAgent (attach-channel closure)** — a shell that closes the JVM attach channel defeats
  *all* attach-based tools, including this one. Countering it needs premain mode (deferred).
- **Windows + JDK 17 NIO Selector bug** — use JDK 8 to run the target, or run it on Linux.
- **Spring Bean cleaning** — out of scope (rollback complexity too high to be safe).
- **Spring Boot 1.x, Tomcat 7 / 8.5 / 11** — not in the test matrix.

## Documentation

- [中文文档 (Chinese README)](README.zh-CN.md)
- [Design notes — full version history & architecture (Chinese)](java_memshell_scanner_design.md)
- [Contributing](CONTRIBUTING.md)

## Roadmap (post-1.0)

- HTML / Markdown reports
- Container / Kubernetes adaptation
- premain mode to counter antiAgent attach-channel closure

## License

Apache License 2.0 — see [LICENSE](LICENSE).
