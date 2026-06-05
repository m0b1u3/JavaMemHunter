**English** | [中文](README.zh-CN.md)

# JavaMemHunter

> Detect, score, clean, and verify Java memory-resident webshells in
> Tomcat / Spring Boot applications — at runtime, via Java Agent attach.

[![Test](https://github.com/m0b1u3/JavaMemHunter/actions/workflows/test.yml/badge.svg)](https://github.com/m0b1u3/JavaMemHunter/actions/workflows/test.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

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

## Supported environments

| Component   | Versions verified                                                       |
|-------------|-------------------------------------------------------------------------|
| JDK         | 17 (CI); 8 manual on Windows (NIO selector workaround)                  |
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

- [中文详细文档 (full Chinese docs)](README.zh-CN.md)
- [Design notes (Chinese)](java_memshell_scanner_design.md)
- [Contributing](CONTRIBUTING.md)
- [Version history](README.zh-CN.md#版本演进)

## Roadmap (post-1.0)

- HTML / Markdown reports
- Container / Kubernetes adaptation
- premain mode to counter antiAgent attach-channel closure

## License

Apache License 2.0 — see [LICENSE](LICENSE).
