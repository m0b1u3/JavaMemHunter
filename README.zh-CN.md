[English](README.md) | **中文**

# JavaMemHunter

[![Test](https://github.com/m0b1u3/JavaMemHunter/actions/workflows/test.yml/badge.svg)](https://github.com/m0b1u3/JavaMemHunter/actions/workflows/test.yml)
[![Release](https://img.shields.io/badge/release-v1.0-blue.svg)](https://github.com/m0b1u3/JavaMemHunter/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![JDK](https://img.shields.io/badge/JDK-8%2B-orange.svg)](#兼容性)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

Java 内存马应急工具：运行时 attach 检测 + 评分 + 终端摘要（带访问路径）+ 原子清理 + 复核。实测可检出冰蝎 Agent 马、哥斯拉伪装 Filter 马、JSP webshell，critical/high 两层零误报零漏报。

## 能检出什么（按实战马型）

| 马型 | 怎么藏 | 怎么检出 |
|---|---|---|
| **冰蝎（Behinder）Agent 马** | `redefineClasses` 篡改 `HttpServlet.service` 字节码 | 内存 vs 磁盘 jar 字节码指纹比对；提取注入的访问 URI / 解密类名 |
| **哥斯拉（Godzilla）Filter 马** | Jackson 类改包名成 `org.apache.coyote.*` 动态注入 | 伪装包名检测（框架包名 + 无 jar 来源）；依赖类降级到 high |
| **JSP webshell** | 磁盘 `.jsp` 文件，编译成 `org.apache.jsp.*` | 类名反推 `.jsp` 访问 URL |
| **Tomcat Filter / Servlet / Listener / Valve** | 运行时注册进容器，无 class 文件 | 容器注册表扫描 + runtime-only / 通配 urlPattern 启发式 |
| **Spring Interceptor / Mapping** | 注入 `AbstractHandlerMapping` / `RequestMappingHandlerMapping` | Spring 运行时扫描 |

## 清理能力总览

| Finding type | 扫描 | 清理 | 清理手段 |
|---|---|---|---|
| `tomcat-filter` | ✅ | ✅ TomcatFilterCleaner | filterDefs/Maps/Configs 原子副本替换 |
| `tomcat-servlet` | ✅ | ✅ TomcatServletCleaner | children/servletMappings 原子副本替换 |
| `tomcat-listener-{request,session,context,other}` | ✅ | ✅ TomcatListenerCleaner | applicationEventListeners / applicationLifecycleListeners 副本替换 |
| `tomcat-valve` | ✅ | ✅ TomcatValveCleaner | Pipeline 链表重接 |
| `spring-mapping` | ✅ | ✅ SpringMappingCleaner | 官方 `unregisterMapping(info)` |
| `spring-interceptor` | ✅ | ✅ SpringInterceptorCleaner | adaptedInterceptors 跨多 bean 副本替换 |
| `agent-bytecode-tampered`（冰蝎 redefine） | ✅ | — | 字节码篡改型，需重启 / 人工处置 |
| `class-*`（JVM 类层面） | ✅ | — | 扫描类用于评分；JSP webshell 该删磁盘 .jsp 文件 |

**所有清理都是：** dry-run（落盘计划+证据）→ attach 端 `yes` 二次确认 → confirm（原子替换 + 验证 + 失败回滚）→ verify（独立复扫确认）。

## 扫描输出示例（终端摘要，脱敏）

```
[memhunter] scan summary (PID <pid>):
  critical: 4  high: 9  suspicious: 0  low: 67
  [critical] tomcat-filter  org.apache.coyote.JavaType  score=16  path=[/*]
  ...（4 个哥斯拉注册 Filter 马，全带 path=[/*]）
  [high] class-servlet  org.apache.coyote.util.EnumValues  score=8        （Jackson 依赖类，已降级）
  [high] class-servlet  org.apache.jsp.<obfuscated>_jsp  score=7  path=[/<obfuscated>.jsp]
  [high] tomcat-servlet  <null>  score=8  path=[/<shell-path>]
[memhunter] full report: ./memhunter-scan-<timestamp>.json
```

只列 critical/high/suspicious，low 仅计数不刷屏。`path=` 是可封堵的访问路径；`trigger=`/`pipeline=` 是无 URL 的事件/管道型；JSP 的 path 指向待删磁盘文件。完整 JSON 报告保留全量 finding（含 low）供取证。

## 快速开始

### 构建

```bash
./mvnw package -DskipTests
```

Windows Git Bash：
```bash
cmd //c "mvnw.cmd package -DskipTests"
```

产物：`attach/target/memhunter-attach.jar`、`agent/target/memhunter-agent.jar`、`test-target/target/memhunter-test-target.jar`。

### 扫描 + 清理 + 复核

```bash
# 1. 列出 Java 进程
java -jar attach/target/memhunter-attach.jar list

# 2. 扫描（可选：带基线对比 + 详细规则）
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar \
    scan --baseline clean-baseline.json --output now.json --explain

# 3. 生成清理计划（dry-run，不修改运行时）
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar \
    clean --id <findingId> --dry-run --evidence-dir ./evidence-root

# 4. 人工审阅 evidence-root/evidence/<findingId>/clean-plan.json

# 5. 确认执行（stdin 必须严格输入小写 yes）
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar \
    clean --id <findingId> --confirm --evidence-dir ./evidence-root

# 6. 独立复核
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar \
    verify --id <findingId> --evidence-dir ./evidence-root
```

生产环境建议：清理完成后仍应在维护窗口重启服务，避免业务框架或第三方组件保留运行时缓存引用。

## CLI 参数

| 参数 | 命令 | 说明 |
|---|---|---|
| `--output <file>` | scan | 报告输出路径（可选，默认写到当前目录 `memhunter-scan-<时间戳>.json`）。无论是否指定，终端都打印精简摘要（逐条 critical/high/suspicious + low 计数）并显示报告全路径。路径不能含空格（agent 参数按空白切分） |
| `--baseline <file>` | scan | 历史 ScanReport JSON；不在基线中的 finding 命中 `baseline-new` (+4) |
| `--whitelist <file>` | scan | 用户白名单，每行 `<type>:<value>`，`<type>` ∈ {framework, business, agent, codesource} |
| `--explain` | scan | 在每个 finding 中输出 `ruleHits` 明细 |
| `--id <findingId>` | clean / verify | 目标 finding ID（来自 scan 报告） |
| `--dry-run` | clean | 生成 `clean-plan.json` + 证据包，不修改运行时 |
| `--confirm` | clean | 读取 dry-run 计划，stdin `yes` 确认后执行 |
| `--force` | clean | 跳过 score < 7 闸门；持久化和 confirm 标志必须一致 |
| `--evidence-dir <dir>` | clean / verify | 证据目录根（默认当前目录） |

### 白名单文件示例

```text
business:com.mycompany.app.
framework:com.acme.shared.
agent:com.custom.tracer
codesource:/opt/myapp/
```

### 清理证据目录结构

```text
<evidence-dir>/evidence/<findingId>/
├── finding.json           # 原始 Finding（含 score/level/reasons）
├── clean-plan.json        # dry-run 生成；confirm 时严格比对 4 字段
├── before-snapshot.json   # 反射读出的 Tomcat/Spring 内部结构快照
├── clean-result.json      # confirm 后写出（success/rolledBack/verifiedDisappeared/executedSteps）
└── verify-result.json     # 独立 verify 命令写出
```

## 兼容性

| 环境 | 验证情况 |
|---|---|
| JDK | 目标 JVM JDK 8 / 11 / 17 / 21（agent 为 JDK 8 字节码）；JDK 17 需加 `--add-opens`，见下 |
| Tomcat | 9.x（含 9.0.94 独立部署，实测）、10.x（Spring Boot 3.2） |
| Spring Boot | 2.7.x、3.2.x |
| 操作系统 | Linux（CI）、Windows 11（手动） |
| 实测马型 | 冰蝎 Agent 马、哥斯拉 Filter 马、JSP webshell（实地手动验证） |

## 限制

- **JDK 17+ 需给目标 JVM 加 `--add-opens`**。Agent 反射遍历 Thread/field graph 定位 Tomcat `StandardEngine`，JDK 9+ 模块封装会阻止此反射，必须在启动目标时加：

  ```
  java --add-opens=java.base/java.lang=ALL-UNNAMED \
       --add-opens=java.base/java.lang.reflect=ALL-UNNAMED \
       --add-opens=java.base/java.util=ALL-UNNAMED \
       --add-opens=java.base/java.util.concurrent=ALL-UNNAMED \
       -jar your-app.jar
  ```

  不加则退化到精度更差的 class-loaded 模式，cleaner 无法工作。JDK 8 无模块系统，无需此 flag。
- **`--output` 路径不能含空格** —— attach→agent 参数管道按空白切分，含空格路径会被明确报错拒绝。
- **antiAgent（封 attach 通道）** —— 关闭 JVM attach 通道的马会让所有 attach 工具失效（包括本工具）；对抗需 premain 模式（后续）。
- **Windows + JDK 17 NIO Selector bug** —— 用 JDK 8 启动目标，或在 Linux 运行。
- **Spring Bean 清理** —— 超出范围（回滚复杂度过高不安全）。
- **Spring Boot 1.x、Tomcat 7 / 8.5 / 11** —— 不在测试矩阵。

## 文档

- [English README](README.md)
- [设计文档（含完整版本演进与架构）](java_memshell_scanner_design.md)
- [贡献指南](CONTRIBUTING.md)

## 路线图（v1.0 之后）

- HTML / Markdown 报告
- 容器 / Kubernetes 适配
- premain 模式对抗 antiAgent 封 attach 通道

## License

Apache License 2.0 —— 见 [LICENSE](LICENSE)。
