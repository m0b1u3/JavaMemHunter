# JavaMemHunter

Java 内存马扫描与清理工具（v0.6 — Tomcat Filter 安全清理 + 基线对比 + 字节码扫描 + 评分规则引擎 + 白名单）。

## v0.6 能力

在 v0.5 基础上新增：

- **Tomcat Filter 安全清理**：支持 `clean --id <id> --dry-run` 生成清理计划和证据包，再通过 `clean --id <id> --confirm` 二次确认后执行。
- **清理证据目录**：默认写入 `evidence/<findingId>/`，包含 `finding.json`、`clean-plan.json`、`before-snapshot.json`、`clean-result.json`、`verify-result.json` 等文件。
- **原子副本替换 + 回滚**：清理顺序为 `filterConfigs -> filterMaps -> filterDefs`，失败时尽量按反向顺序回滚。
- **清理后验证**：支持 `verify --id <id>` 复扫确认 finding 是否仍存在；v0.6 E2E 已验证 FakeFilter 清理后 `stillPresent=false`。
- **attach 侧交互确认**：`clean --confirm` 会读取 dry-run 生成的计划摘要，stdin 必须严格输入小写 `yes` 才会执行。

### 清理命令

```bash
# 1. 先生成清理计划和证据包
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar clean --id <findingId> --dry-run --evidence-dir ./evidence-root

# 2. 人工审阅 evidence-root/evidence/<findingId>/clean-plan.json 后确认
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar clean --id <findingId> --confirm --evidence-dir ./evidence-root

# 3. 独立复核 finding 是否仍存在
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar verify --id <findingId> --evidence-dir ./evidence-root
```

生产环境建议：清理完成后仍应在维护窗口重启服务，避免业务框架或第三方组件保留运行时缓存引用。

## v0.5 能力

在 v0.4 基础上新增：

- **基线对比**：扫描时与历史 ScanReport 对比，新增 finding 会命中 `baseline-new` 并加分。这是识别“启动后被注入”组件的核心信号
- **`baseline-new` 评分规则**（+4）：对所有 finding type 生效，与白名单独立累加
- **CLI 新增 `--baseline <file>`**：复用已有 ScanReport JSON，不引入新的基线文件格式
- **Summary 新增字段**：`baselineNewCount` / `baselineMatchedCount`，便于快速判断本次扫描相对基线新增了多少对象
- **Finding ID 稳定性修复**：Listener / Interceptor ID 不再包含 `identityHashCode`，跨 JVM 重启稳定
- **字节码 INVOKEDYNAMIC 支持**：可识别 lambda / invokedynamic bootstrap args 中隐藏的可疑 method handle
- **BytecodeAnalysis 加固**：`methodCalls` 改为不可变 Set，并新增 `hasMethodCallByOwnerPrefix` helper

## v0.4 能力

在 v0.3 基础上新增：

- **字节码扫描**：通过 ASM 9.7 读取目标类的 .class 字节流，精确匹配 method call（owner + name）而非字符串包含，避免误报
- **5 条字节码规则**（覆盖 RCE 攻击者必须使用的 API）：
  - `bytecode-runtime-exec`（+4）：`Runtime.getRuntime().exec(...)`
  - `bytecode-process-builder`（+4）：`new ProcessBuilder(...).start()`
  - `bytecode-define-class`（+3）：`ClassLoader.defineClass(...)` 动态加载字节码
  - `bytecode-reflection-abuse`（+2）：`setAccessible` / `getDeclaredField` / `getDeclaredMethod`
  - `bytecode-crypto`（+2）：`Cipher.doFinal` / `Base64.Decoder` 加解密通信
- **lazy 字节码缓存**：ScanContext 持有 `bytecodeOf(className)` 缓存；单次扫描每个类至多解析一次
- **效果**：v0.3 中 FakeFilter / FakeServlet / FakeInterceptor 注入项 score 从 10-12 进一步升至 17-21（全部 critical）；类层面 finding 同时获得字节码加分
- **死代码清理**：删除 ClassLoadedContextProvider 约 80 行 v0.2 遗留代码

## v0.3 能力

在 v0.2 基础上新增：

- **12 条评分规则**：覆盖类型识别、CodeSource 异常、运行时存在、URL pattern 通配、类名熵、包名归属、ClassLoader 异常、路径伪装等多维度判定
- **白名单系统**：内置 Spring/Tomcat/Jackson 等框架包名、APM Agent 名和可信 CodeSource 路径；用户可通过 `--whitelist <file>` 追加业务包名
- **4 级风险等级**：`low (0-3)` / `suspicious (4-6)` / `high (7-9)` / `critical (10+)`
- **`--explain` 详细模式**：报告中加入 `ruleHits` 数组，展示每条命中规则的得分
- **误报压降**：v0.2 中 WsFilter、StandardContextValve 等框架组件通过白名单降回 low；FakeFilter、FakeServlet、FakeInterceptor 升至 critical

## v0.2 能力

在 v0.1 基础上新增：

- **Tomcat 容器内部扫描**：定位 `StandardContext` 并枚举其 Filter、Servlet、Listener、Valve 注册表（含 URL pattern、dispatcherTypes、loadOnStartup、pipeline index 等属性）
- **Spring 运行时扫描**：枚举 `RequestMappingHandlerMapping` 中的 HandlerMethod 与 `HandlerInterceptor` 列表
- **runtime-only 评分规则**：对容器/Spring 中存在但**类上没有 @WebFilter/@WebServlet/@WebListener 注解、也不是 Spring Bean** 的对象自动标 `suspicious` 并加分
- **Listener 子类型细分**：v0.2 将 `class-listener` 拆为 `class-listenerrequest`、`class-listenercontext`、`class-listenersession` 三类
- **多 Context 支持**：自动遍历同 JVM 中的所有 Tomcat StandardContext（多应用部署场景）
- **跨版本反射**：通过 `ReflectUtil` 工具处理 Tomcat 7-10、Spring 5.x/6.x 内部字段差异
- **报告原子写入**：写到 `<path>.tmp` 然后 rename，避免 JVM 被中断时残留半写入文件
- **CLI 选项校验**：未知 `--option` 输出 stderr 警告（如 `--ouput` typo）
- **BFS 接口环防护**：`WebComponentDetector` 改用 visited Set + BFS，防御恶意 class file 构造的接口环

v0.1 已有能力保留：JVM 类枚举、Web 组件接口识别、稳定 Finding ID、JSON 报告。

## 架构

```text
memhunter-attach.jar          — 外部 CLI（JDK 11+）
memhunter-agent.jar           — Java Agent fat jar（JDK 8 字节码，含 Jackson）
memhunter-test-target.jar     — Spring Boot 2.7 测试应用
memhunter-test-target-injector — 模拟内存马注入器（仅测试用，**勿放生产**）
```

通信：`agentmain` 阻塞执行 + 报告原子写入到本地文件。不使用 Socket（避免容器网络隔离问题）。

### v0.2 扫描器结构

```text
agent/scanner/
├── ClassScanner.java          # 类层面扫描（v0.1 行为）
├── WebComponentDetector.java  # BFS 接口检测，含 Listener 子类型
├── tomcat/                    # Tomcat 容器扫描
│   ├── TomcatScanner          # 入口，遍历所有 Context
│   ├── StandardContextProvider 链
│   │   ├── MBeanContextProvider          (Catalina:type=Context 查询)
│   │   └── ClassLoadedContextProvider    (WebappClassLoader / Thread-walk 兜底)
│   ├── TomcatFilterScanner    # filterDefs + filterMaps + filterConfigs
│   ├── TomcatServletScanner   # StandardWrapper 枚举
│   ├── TomcatListenerScanner  # applicationEventListeners / applicationLifecycleListeners
│   └── TomcatValveScanner     # Pipeline 链表
├── spring/                    # Spring 运行时扫描
│   ├── SpringScanner          # 入口
│   ├── ApplicationContextProvider 链
│   │   ├── DispatcherServletProvider     (主路径)
│   │   └── ServletContextAttrProvider    (兜底)
│   ├── SpringMappingScanner   # AbstractHandlerMethodMapping → HandlerMethod
│   └── SpringInterceptorScanner # adaptedInterceptors
└── scoring/                   # v0.3 评分规则引擎
    ├── RuleEngine             # 统一计算 score / level / reasons
    ├── Whitelist              # framework / business / agent / codesource 白名单
    └── rules/                 # 12 条 ScoringRule
```

## 构建

```bash
./mvnw package -DskipTests
```

Windows Git Bash：
```bash
cmd //c "mvnw.cmd package -DskipTests"
```

产物：
- `attach/target/memhunter-attach.jar`
- `agent/target/memhunter-agent.jar`
- `test-target/target/memhunter-test-target.jar`
- `test-target-injector` 作为依赖打入 test-target

## 使用

### 列出 Java 进程

```bash
java -jar attach/target/memhunter-attach.jar list
```

### 执行扫描

```bash
java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar scan --output /tmp/report.json
```

v0.3 新增参数：

- `--whitelist <file>`：追加用户白名单。文件格式为每行 `<type>:<value>`，其中 `<type>` 可为 `framework`、`business`、`agent`、`codesource`。

  ```text
  business:com.mycompany.app.
  framework:com.acme.shared.
  agent:com.custom.tracer
  codesource:/opt/myapp/
  ```

- `--explain`：在每个 finding 中输出 `ruleHits`，展示每条命中规则和加分/减分明细。

- `--baseline <file>`：基线对比文件，格式为任意历史 ScanReport JSON。当前扫描中所有 `finding.id` 不在 baseline 中的对象会命中 `baseline-new` +4。

  ```bash
  # 1. 系统启动后先打干净基线
  java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar scan --output clean-baseline.json

  # 2. 应急排查时带基线对比
  java -jar attach/target/memhunter-attach.jar <PID> agent/target/memhunter-agent.jar scan --baseline clean-baseline.json --output now.json --explain
  ```

## Finding 类型表

| Finding type | 含义 | 关键 attributes |
|---|---|---|
| `class-filter` / `class-servlet` / `class-valve` / `class-interceptor` | 类层面发现（v0.1） | — |
| `class-listenerrequest` / `class-listenercontext` / `class-listenersession` | Listener 子类型（v0.2 细分） | — |
| `tomcat-filter` | StandardContext.filterDefs 注册的 Filter | filterClass, urlPatterns, dispatcherTypes, contextPath |
| `tomcat-servlet` | StandardContext.children 中的 Wrapper | servletClass, mappings, loadOnStartup, contextPath |
| `tomcat-listener-request/session/context/other` | applicationEventListeners + applicationLifecycleListeners | listenerKind, contextPath |
| `tomcat-valve` | Context Pipeline 中的 Valve | containerLevel, pipelineIndex, contextPath |
| `spring-mapping` | AbstractHandlerMethodMapping 注册的 mapping | pattern, methods, handlerMethod, beanName |
| `spring-interceptor` | AbstractHandlerMapping.adaptedInterceptors | order, includePatterns, excludePatterns |

## 评分规则参考（v0.5）

| Rule | 命中条件 | Delta |
|---|---|---|
| `implements-web-component` | type 为 class-*/tomcat-*/spring-* | +3 |
| `code-source-null` | finding.codeSource == null | +3 |
| `code-source-temp-dir` | codeSource 包含 /tmp、/var/tmp 或 AppData/Local/Temp | +3 |
| `runtime-only` | 无 @Web* 注解，也非 Spring Bean | +4 |
| `url-pattern-wildcard` | urlPatterns 含 /* 或 / | +2 |
| `filter-order-at-top` | pipelineIndex/order <= 1 | +2 |
| `high-entropy-class-name` | 简单类名 Shannon 熵 > 3.5 | +1 |
| `non-business-package` | 非 framework 且非 business 包 | +2 |
| `unusual-classloader` | classLoader 不在常见列表 | +2 |
| `mapping-path-disguise` | pattern 类似健康检查但类不在 framework | +2 |
| `whitelist-hit` | 类名以 framework 包名开头或 CodeSource 可信 | -5 |
| `apm-agent` | 类名含 APM Agent 标识 | -4 |
| `bytecode-runtime-exec` | 字节码调用 `java/lang/Runtime#exec` | +4 |
| `bytecode-process-builder` | 字节码调用 `ProcessBuilder#<init>` 或 `#start` | +4 |
| `bytecode-define-class` | 字节码调用任何 `defineClass` 方法 | +3 |
| `bytecode-reflection-abuse` | 字节码调用 `setAccessible` / `getDeclaredField` / `getDeclaredMethod` | +2 |
| `bytecode-crypto` | 字节码调用 `Cipher#doFinal` 或 `Base64*` | +2 |
| `baseline-new` | finding.id 不在 baseline 中 | +4 |

等级阈值：`0-3 low / 4-6 suspicious / 7-9 high / 10+ critical`

## runtime-only 判定

对每个 `tomcat-*` 和 `spring-*` finding，两链检查（任一命中即不标 runtime-only，维持 level=low）：

1. 类上是否有 `@WebFilter` / `@WebServlet` / `@WebListener` 注解（javax + jakarta 双命名空间）
2. 类是否在 Spring ApplicationContext 的 BeanDefinition 中

全部 miss → reasons 追加 `"runtime-only"`，level 从 `low` 升至 `suspicious`，score +3。

> v0.2 设计文档初版有第三链（web.xml 检查），但代码评审发现 ServletContext.getFilterRegistration() 对程序化注册的 Filter 也返回非 null（与 web.xml 注册无法区分），会让 v0.2 demo 用 `addFilter()` 注册的 FakeFilter 误判为合法。修复决定移除第三链；annotation + Spring Bean 两链已足够。

## 端到端验证

启动 Spring Boot 测试目标后，注入器模块提供 4 个端点模拟内存马注入：

```bash
java -Djava.net.preferIPv4Stack=true -jar test-target/target/memhunter-test-target.jar &

curl http://localhost:8080/inject/filter           # 反射插入 FilterDef + FilterMap + ApplicationFilterConfig
curl http://localhost:8080/inject/servlet          # 反射创建 Wrapper 并 addChild + addServletMappingDecoded
curl http://localhost:8080/inject/spring-mapping   # 反射 RequestMappingHandlerMapping.registerHandlerMethod
curl http://localhost:8080/inject/spring-interceptor # 直接 mutate adaptedInterceptors

PID=$(java -jar attach/target/memhunter-attach.jar list | grep memhunter-test-target | awk '{print $1}')
java -jar attach/target/memhunter-attach.jar $PID agent/target/memhunter-agent.jar scan
```

v0.3 样例报告：[`docs/superpowers/specs/v0.3-sample-report.json`](docs/superpowers/specs/v0.3-sample-report.json) — 63 findings。FakeFilter、FakeServlet、FakeInterceptor 均为 critical；WsFilter、StandardContextValve 通过白名单降为 low。

## 兼容性

| 组件 | 编译目标 | 运行环境 |
|---|---|---|
| attach | JDK 11+ 字节码 | JDK 11+ |
| agent | JDK 8 字节码 | 目标 JVM JDK 8 / 11 / 17 / 21 |
| test-target | JDK 8 字节码（Spring Boot 2.7） | JDK 8+ |

### 已知环境 issue：JDK 17 + Windows 11 NIO Selector bug

某些 Windows 11 环境上 JDK 17 创建 NIO Selector 时 `UnixDomainSockets.connect0` 抛 `SocketException: Invalid argument: connect`，导致 Tomcat acceptor 启动失败。Workaround：用 JDK 8 启动 test-target。Agent JAR 仍是 JDK 8 字节码，可以 attach 到 JDK 8 / 11 / 17 / 21 任意目标 JVM。

### Tomcat Context 定位策略

- **MBeanContextProvider**：查询 `Catalina:type=Context,*` MBean → managedResource。**Spring Boot 内嵌 Tomcat 默认不注册这些 MBean，此路径会返回空**。
- **ClassLoadedContextProvider**：兜底链
  - WebappClassLoader → resources.context（标准 Tomcat 部署用）
  - Engine 静态字段扫描（少数老 Tomcat）
  - **Thread-walk 兜底**：扫描 `http-nio-*-Acceptor/Poller/exec-*` 线程的字段图，最深 12 层，找到 Engine 实例（Spring Boot 场景下唯一可靠路径）

## 限制

v0.6 仍**不包含**：

- WebFlux 应用（不支持）
- Tomcat Servlet / Listener / Valve 清理
- Spring Mapping / Interceptor 清理
- HTML / Markdown 报告
- v0.2 评审遗留 #2/#3/#4：Provider strategies 重构、FindingClassMetadata 抽取、ScanContext 解耦
- 完整路线图见 [`java_memshell_scanner_design.md`](java_memshell_scanner_design.md) 第 25 节

## 单元测试

```bash
cmd //c "mvnw.cmd -pl agent test"
```

v0.6 当前含 159 个 agent 单元测试、12 个 attach 单元测试，新增覆盖：
- `TomcatFilterCleaner` / `RollbackManager` — dry-run 计划、Phase C/D/E、强类型 filterMaps 数组、失败回滚
- `EvidenceWriter` / `CleanPlanReader` — 清理证据包读写
- `VerifyExecutor` — `verify-result.json` 输出
- `CleanInteractor` / `AttachMain` — stdin 严格 `yes` 确认、clean/verify CLI 分发

v0.5 含 112 个 agent 单元测试，新增覆盖：
- `ReflectUtil`（9）— 跨版本反射工具
- `WebComponentDetector`（6）— BFS 接口检测 + Listener 细分
- `AgentArgs`（7）— 未知选项告警 + `--whitelist` / `--explain` / `--baseline`
- `Whitelist`（5）— 默认白名单 + 用户文件追加
- `RuleEngine`（8）— 分数累计、等级映射、explain、异常隔离、默认规则装配
- `BaselineIndex` / `BaselineLoader` / `BaselineNewRule`（15）— 基线 ID 集合、ScanReport 读取、新增 finding 加分
- `MemHunterAgent`（2）— Summary 统计与 baseline matched/new 计数
- `JsonReportWriter`（2）— 原子写入 + 覆盖已有文件
- `FindingIdGenerator`（3）— v0.1 保留

容器层 Scanner（TomcatScanner / SpringScanner / 各子 Scanner）通过 Task 20 端到端集成验证，未做单元测试（Tomcat/Spring 对象 mock 成本高）。

## 开发文档

- 设计文档：[`java_memshell_scanner_design.md`](java_memshell_scanner_design.md)（含 v0.1 ~ v1.0 全部里程碑）
- v0.1 实施计划：[`docs/superpowers/plans/2026-05-18-v0.1-minimal-scan.md`](docs/superpowers/plans/2026-05-18-v0.1-minimal-scan.md)
- v0.1 样例报告：[`docs/superpowers/specs/v0.1-sample-report.json`](docs/superpowers/specs/v0.1-sample-report.json)
- v0.2 设计文档：[`docs/superpowers/specs/2026-05-19-v0.2-container-scanning-design.md`](docs/superpowers/specs/2026-05-19-v0.2-container-scanning-design.md)
- v0.2 实施计划：[`docs/superpowers/plans/2026-05-19-v0.2-container-scanning.md`](docs/superpowers/plans/2026-05-19-v0.2-container-scanning.md)
- v0.2 样例报告：[`docs/superpowers/specs/v0.2-sample-report.json`](docs/superpowers/specs/v0.2-sample-report.json)
- v0.3 设计文档：[`docs/superpowers/specs/2026-05-20-v0.3-scoring-rules-design.md`](docs/superpowers/specs/2026-05-20-v0.3-scoring-rules-design.md)
- v0.3 实施计划：[`docs/superpowers/plans/2026-05-20-v0.3-scoring-rules.md`](docs/superpowers/plans/2026-05-20-v0.3-scoring-rules.md)
- v0.3 样例报告：[`docs/superpowers/specs/v0.3-sample-report.json`](docs/superpowers/specs/v0.3-sample-report.json)
- v0.4 设计文档：[`docs/superpowers/specs/2026-05-21-v0.4-bytecode-scanning-design.md`](docs/superpowers/specs/2026-05-21-v0.4-bytecode-scanning-design.md)
- v0.4 实施计划：[`docs/superpowers/plans/2026-05-21-v0.4-bytecode-scanning.md`](docs/superpowers/plans/2026-05-21-v0.4-bytecode-scanning.md)
- v0.4 样例报告：[`docs/superpowers/specs/v0.4-sample-report.json`](docs/superpowers/specs/v0.4-sample-report.json)
- v0.5 设计文档：[`docs/superpowers/specs/2026-05-21-v0.5-baseline-comparison-design.md`](docs/superpowers/specs/2026-05-21-v0.5-baseline-comparison-design.md)
- v0.5 实施计划：[`docs/superpowers/plans/2026-05-21-v0.5-baseline-comparison.md`](docs/superpowers/plans/2026-05-21-v0.5-baseline-comparison.md)
- v0.5 干净基线：[`docs/superpowers/specs/v0.5-clean-baseline.json`](docs/superpowers/specs/v0.5-clean-baseline.json)
- v0.5 注入后报告：[`docs/superpowers/specs/v0.5-after-inject-report.json`](docs/superpowers/specs/v0.5-after-inject-report.json)
- v0.6 设计文档：[`docs/superpowers/specs/2026-05-22-v0.6-tomcat-filter-clean-design.md`](docs/superpowers/specs/2026-05-22-v0.6-tomcat-filter-clean-design.md)
- v0.6 实施计划：[`docs/superpowers/plans/2026-05-22-v0.6-tomcat-filter-clean.md`](docs/superpowers/plans/2026-05-22-v0.6-tomcat-filter-clean.md)
- v0.6 清理 E2E 证据：[`docs/superpowers/specs/v0.6-clean-flow-evidence/`](docs/superpowers/specs/v0.6-clean-flow-evidence/)
