# JavaMemHunter

Java 内存马扫描与清理工具（v0.1 — 最小可用扫描）。

## v0.1 能力

- Attach 到目标 Java 进程（基于 Java SE Attach API）
- 枚举目标 JVM 已加载类（`Instrumentation.getAllLoadedClasses()`）
- 识别实现 Web 组件接口的类：
  - `javax.servlet.Filter` / `jakarta.servlet.Filter`
  - `javax.servlet.Servlet` / `jakarta.servlet.Servlet`
  - 各类 `Listener`（`ServletRequestListener`、`ServletContextListener`、`HttpSessionListener`，javax 与 jakarta 命名空间均覆盖）
  - `org.apache.catalina.Valve`
  - `org.springframework.web.servlet.HandlerInterceptor`
- 输出 JSON 格式扫描报告（含 PID、JDK 版本、OS、稳定 Finding ID、CodeSource、ClassLoader）

## 架构

双 JAR 设计：

- `memhunter-attach.jar` — 外部 CLI，在用户机器上运行，通过 Java Attach API 连接到目标 JVM
- `memhunter-agent.jar` — Java Agent（shaded fat jar，含 Jackson），由 `agentmain` 在目标 JVM 内同步执行

通信采用 **agentmain 阻塞执行 + 文件落盘** 模式：agent 在目标 JVM 内完成扫描后将报告写入指定文件，attach 端等待 agentmain 返回。不使用 Socket 通信，避免容器网络隔离问题。

## 构建

```bash
./mvnw package -DskipTests
```

Windows Git Bash 用：

```bash
cmd //c "mvnw.cmd package -DskipTests"
```

产物：
- `attach/target/memhunter-attach.jar`
- `agent/target/memhunter-agent.jar`（fat jar，自带 Jackson）
- `test-target/target/memhunter-test-target.jar`（Spring Boot 测试目标）

## 使用

### 列出本机 Java 进程

```bash
java -jar attach/target/memhunter-attach.jar list
```

输出示例：

```
PID	Display
15836	some.MainClass
1948	test-target/target/memhunter-test-target.jar
```

### 执行扫描

```bash
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar scan --output /tmp/report.json
```

参数说明：
- `<PID>` — 目标 Java 进程 PID
- `agent/target/memhunter-agent.jar` — agent JAR 路径（绝对或相对都可）
- `scan` — 子命令（v0.1 仅支持 scan）
- `--output <file>`（可选）— 报告输出路径。省略时默认写入 `<java.io.tmpdir>/memhunter-report-<scanId>.json`

报告示例片段：

```json
{
  "scanId" : "scan-8591328f",
  "timestamp" : "2026-05-19T01:31:12.194114700Z",
  "target" : {
    "pid" : 1948,
    "javaVersion" : "17.0.12",
    "os" : "Windows 11"
  },
  "summary" : {
    "totalFindings" : 33,
    "critical" : 0, "high" : 0, "suspicious" : 0, "low" : 33
  },
  "findings" : [ {
    "id" : "finding-class-filter-1b748395",
    "type" : "class-filter",
    "level" : "low",
    "score" : 3,
    "name" : "WsFilter",
    "className" : "org.apache.tomcat.websocket.server.WsFilter",
    "codeSource" : "jar:file:/path/to/app.jar!/BOOT-INF/lib/tomcat-embed-websocket-9.0.83.jar!/",
    "classLoader" : "org.springframework.boot.loader.LaunchedURLClassLoader",
    "reasons" : [ "implements Filter" ],
    "recommendation" : "v0.1 informational only; review manually"
  } ]
}
```

完整样例：[`docs/superpowers/specs/v0.1-sample-report.json`](docs/superpowers/specs/v0.1-sample-report.json)（对 Spring Boot 2.7 内嵌 Tomcat 扫描，33 个 findings）。

### Finding ID

ID 格式 `finding-<type>-<sha256前8位>`，对象特征 hash 输入为 `type + "|" + className + "|" + discriminator`。同一个对象跨多次扫描 ID 保持稳定，可直接用于后续版本的 clean 命令以及基线对比。

## 模块结构

```
JavaMemHunter/
├── attach/         # 外部 CLI，requires JDK 11+（com.sun.tools.attach 需要）
├── agent/          # Java Agent，编译目标 JDK 8（兼容任意 JDK 8+ 目标 JVM）
├── test-target/    # Spring Boot 2.7 测试应用
└── docs/           # 设计文档与计划
```

## 兼容性

| 组件 | 编译目标 | 运行环境 |
|---|---|---|
| attach | JDK 11+ 字节码 | JDK 11+ |
| agent | JDK 8 字节码 | 目标 JVM JDK 8 / 11 / 17 / 21 |
| test-target | JDK 8 字节码（Spring Boot 2.7） | JDK 8+ |

JDK 21+ 会在动态 agent 加载时输出告警，v0.1 接受此告警。

## 限制

v0.1 仅做最小通路验证，**不包含**：
- 容器内部注册表扫描（Tomcat `StandardContext.findFilterDefs()`、Servlet Wrapper、Listener 列表、Valve Pipeline 等）
- Spring `HandlerMapping` / `Interceptor` 运行时枚举
- 字节码两阶段扫描（关键字匹配、hash 计算）
- JDK 17/21 `--add-opens` 动态注入（用于深层反射）
- 白名单 / 基线 / 风险评分规则引擎
- 清理操作（dry-run / confirm 流程）
- HTML / Markdown 报告

完整功能路线图见 [`java_memshell_scanner_design.md`](java_memshell_scanner_design.md)，v0.1 ~ v1.0 各里程碑见设计文档第 25 节。

## 单元测试

```bash
cmd //c "mvnw.cmd -pl agent test"
```

v0.1 含 7 个单元测试，覆盖 `FindingIdGenerator`、`WebComponentDetector`、`JsonReportWriter`。`ClassScanner` 和 `MemHunterAgent` 通过端到端集成验证（扫描 test-target）。

## 开发文档

- 设计文档：[`java_memshell_scanner_design.md`](java_memshell_scanner_design.md)
- v0.1 实施计划：[`docs/superpowers/plans/2026-05-18-v0.1-minimal-scan.md`](docs/superpowers/plans/2026-05-18-v0.1-minimal-scan.md)
- v0.1 样例报告：[`docs/superpowers/specs/v0.1-sample-report.json`](docs/superpowers/specs/v0.1-sample-report.json)
