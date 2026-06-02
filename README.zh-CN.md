[English](README.md) | **中文**

# JavaMemHunter

Java 内存马扫描与清理工具 — **v0.8 当前**：6 类内存马完整闭环（4 Tomcat + 2 Spring），扫描 + 评分 + 基线对比 + 字节码分析 + 安全清理。

## 当前能力总览

| Finding type | 扫描 | 清理 | 清理手段 |
|---|---|---|---|
| `tomcat-filter` | ✅ | ✅ TomcatFilterCleaner | filterDefs/Maps/Configs 原子副本替换 |
| `tomcat-servlet` | ✅ | ✅ TomcatServletCleaner | children/servletMappings 原子副本替换 |
| `tomcat-listener-{request,session,context,other}` | ✅ | ✅ TomcatListenerCleaner | applicationEventListeners / applicationLifecycleListeners 副本替换 |
| `tomcat-valve` | ✅ | ✅ TomcatValveCleaner | Pipeline 链表重接 |
| `spring-mapping` | ✅ | ✅ SpringMappingCleaner | 官方 `unregisterMapping(info)` |
| `spring-interceptor` | ✅ | ✅ SpringInterceptorCleaner | adaptedInterceptors 跨多 bean 副本替换 |
| `class-*`（JVM 类层面） | ✅ | — | （不需要清理，扫描类只用于评分） |

**所有清理都是：** dry-run（落盘计划+证据）→ attach 端 `yes` 二次确认 → confirm（原子替换 + 验证 + 失败回滚）→ verify（独立复扫确认）。

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
| `--output <file>` | scan | 报告输出路径（默认 stdout） |
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

## 版本演进

### v0.8.2 — Audit-Chain 修复（2026-06-01）

修补 v0.8.1 手动 E2E 中发现的三个 audit-chain / verify 漏洞：

1. **VerifyExecutor 只扫 Filter（最严重）**：v0.6 引入的 `VerifyExecutor.stillPresent`
   只跑 `TomcatFilterScanner`。v0.7+v0.8 加了 5 个新 Cleaner（Servlet/Listener/Valve/
   Spring-Mapping/Spring-Interceptor）但 verify 未同步升级，结果对非 Filter 类型
   永远返回 `stillPresent=false`（假阴性，让操作员误判清理成功）。**修复：** 抽
   `findFindingById` 到新 `FindingLocator`；VerifyExecutor 接受 `(tomcatCtx, springCtx)`
   双 context，调 FindingLocator 跑 6 类 scanner。
2. **Force-gate 阻断 dry-run**：`AgentArgs.validate` 拒绝 `--force` 与 `--dry-run` 组合，
   导致 sub-threshold finding（score < 7）无法生成 evidence bundle。**修复：**
   删除该校验；force 跨阶段一致性由 v0.6.1 PlanReconciler 三方一致性闸门保证。
3. **Plan-missing 崩栈**：`clean --confirm` 时若 plan 文件不存在，AttachMain 抛
   Jackson IOException 崩出 17 行 Java 栈。**修复：** AttachMain 提前 `Files.exists`
   检查；缺失则友好打印 `"plan file not found at <path>; run --dry-run first"`
   并返回 `2` (EXIT_USAGE)，不触达 agent。

无新 CLI 选项；evidence schema 不变；既有 binary 完全兼容（`VerifyExecutor` 单
参构造器保留为 `@Deprecated`）。

### v0.8 — Spring Cleaners 扩展（2026-05-29）

把清理能力从 Tomcat 4 类扩展到 Spring MVC 两类（Mapping / Interceptor）。CLI 不变；MemHunterAgent 同时扫描 Tomcat + Spring，按 `finding.type` 路由到对应 Cleaner。

**架构变更：**

1. **AbstractCleaner**：容器无关的模板基类（plan/execute/Phase-D/Phase-E）。AbstractTomcatCleaner 与新的 AbstractSpringCleaner 都继承它。
2. **CleanerRegistry**：register 增加 `ContextKind`（TOMCAT/SPRING）；resolve 按类型路由对应 context。
3. **SpringMappingCleaner**：Phase B 通过 `String.valueOf(info)` + className 重定位活的 RequestMappingInfo，Phase C 调官方 `unregisterMapping`，rollback 用 `registerMapping` 重新注册（优先用 `HandlerMethod.getBean()`）。
4. **SpringInterceptorCleaner**：跨所有 HandlerMapping bean 的 `adaptedInterceptors` 做原子副本替换（同一 interceptor 可能注册到多个 bean）。
5. **CleanExecutionException.didMutate**：区分"未动运行时的前置失败"与"已动并回滚的前向失败"，让 `rolledBack` 标志准确（同时修掉 v0.7 Valve nit）。
6. **SpringMappingCleaner Phase C bug 修复**：unregister 失败不再触发 rollback（避免 `registerMapping` 双注册）。

**范围说明：** v0.8 只注销 Spring 路由 / 移除 interceptor；handler bean 仍留在 BeanFactory（**Spring Bean 清理留 v0.9**）。

### v0.7.1 — Tomcat Cleaners E2E + Listener 兼容（2026-05-28）

- 归档真实 `test-target` E2E 清理流程证据到 `docs/superpowers/specs/v0.7.1-clean-flow-evidence/`，覆盖 `tomcat-filter` / `tomcat-servlet` / `tomcat-listener-request` / `tomcat-valve` 的 dry-run / confirm / verify / before-after scan artifacts
- 修复 Tomcat 9 Listener 兼容性：scan/clean 同时支持 getter/setter API 和 legacy/new listener storage 字段名

### v0.7 — Tomcat Cleaners 扩展（2026-05-26）

把 v0.6 的 Tomcat Filter 清理能力扩展到 Servlet / Listener / Valve 三类。

**架构变更：**

1. **CleanPlan schema**：`filterName/filterClass/urlPatterns` → `targetName/targetClass + details: Map<String,Object>`。details 携带类型专属信息。
2. **CleanerRegistry**：type → Cleaner factory 查表（equals + prefix，exact 优先）。
3. **AbstractTomcatCleaner**：模板基类共享 Phase A/D/E，子类填 Phase B/C。
4. **RollbackStrategy**：从单一 RollbackManager 抽象为接口，每个 Cleaner 自带 strategy。
5. **PlanReconciler**：`filterClass` 比对改名 `targetClass`，三方一致性行为不变。

**重要不兼容：** v0.6 老 evidence 文件不可用于 v0.7+ confirm（schema 不匹配会被 PlanReconciler 拒绝并返回 `EXIT_PLAN_STALE`）。操作员需对每个 finding 重跑 dry-run。

### v0.6.1 — Clean 流程审计链修复（2026-05-22）

修复三项审计链安全问题：

1. **计划过时校验**：`clean --confirm` 将持久化 `clean-plan.json` 与新生成计划在 `findingId / targetClass / score / forced` 四字段做比对。任何不一致直接短路 `CleanResult.success=false`（`EXIT_PLAN_STALE=3`）；runtime 不会被修改。
2. **forced 标志三方一致性**：`--force` 在 confirm 时必须同时等于持久化计划的 `forced` 字段和新生成计划的 `forced` 字段。
3. **Phase D 步骤标签精度**：`executedSteps` 区分 `phase-D: destroy-ran`、`phase-D: no-release-method`、`phase-D: destroy-threw: <Class>: <msg>`（所有 Throwable 仍被容忍；Phase D 不触发回滚）。

### v0.6 — Tomcat Filter 安全清理（2026-05-22）

- **Tomcat Filter 安全清理**：`clean --id <id> --dry-run` 生成清理计划和证据包，再通过 `clean --id <id> --confirm` 二次确认后执行
- **清理证据目录**：默认写入 `evidence/<findingId>/`
- **原子副本替换 + 回滚**：清理顺序 `filterConfigs → filterMaps → filterDefs`，失败时按反向顺序回滚
- **清理后验证**：`verify --id <id>` 复扫确认 finding 是否仍存在
- **attach 侧交互确认**：`clean --confirm` 读取 dry-run 生成的计划摘要，stdin 必须严格输入小写 `yes`

### v0.5 — 基线对比（2026-05-21）

- **基线对比**：扫描时与历史 ScanReport 对比，新增 finding 命中 `baseline-new` (+4)。识别"启动后被注入"组件的核心信号
- **CLI 新增 `--baseline <file>`**：复用已有 ScanReport JSON
- **Summary 新增字段**：`baselineNewCount` / `baselineMatchedCount`
- **Finding ID 稳定性修复**：Listener / Interceptor ID 不再包含 `identityHashCode`，跨 JVM 重启稳定
- **字节码 INVOKEDYNAMIC 支持**：可识别 lambda / invokedynamic bootstrap args 中隐藏的可疑 method handle
- **BytecodeAnalysis 加固**：`methodCalls` 改为不可变 Set，新增 `hasMethodCallByOwnerPrefix` helper

### v0.4 — 字节码扫描（2026-05-21）

- **字节码扫描**：通过 ASM 9.7 读取目标类的 `.class` 字节流，精确匹配 method call（owner + name）而非字符串包含
- **5 条字节码规则**：
  - `bytecode-runtime-exec` (+4)：`Runtime.getRuntime().exec(...)`
  - `bytecode-process-builder` (+4)：`new ProcessBuilder(...).start()`
  - `bytecode-define-class` (+3)：`ClassLoader.defineClass(...)` 动态加载字节码
  - `bytecode-reflection-abuse` (+2)：`setAccessible` / `getDeclaredField` / `getDeclaredMethod`
  - `bytecode-crypto` (+2)：`Cipher.doFinal` / `Base64.Decoder`
- **lazy 字节码缓存**：ScanContext 持有 `bytecodeOf(className)` 缓存；单次扫描每个类至多解析一次

### v0.3 — 评分规则与白名单（2026-05-20）

- **12 条评分规则**：覆盖类型识别、CodeSource 异常、运行时存在、URL pattern 通配、类名熵、包名归属、ClassLoader 异常、路径伪装等
- **白名单系统**：内置 Spring/Tomcat/Jackson 等框架包名、APM Agent 名和可信 CodeSource 路径；用户可通过 `--whitelist <file>` 追加业务包名
- **4 级风险等级**：`low (0-3)` / `suspicious (4-6)` / `high (7-9)` / `critical (10+)`
- **`--explain` 详细模式**：报告中加入 `ruleHits` 数组，展示每条命中规则的得分

### v0.2 — 容器扫描（2026-05-19）

- **Tomcat 容器内部扫描**：定位 `StandardContext` 并枚举 Filter / Servlet / Listener / Valve 注册表
- **Spring 运行时扫描**：枚举 `RequestMappingHandlerMapping` 的 HandlerMethod 与 `HandlerInterceptor` 列表
- **runtime-only 评分规则**：对容器/Spring 中存在但**类上没有 `@WebFilter/@WebServlet/@WebListener` 注解、也不是 Spring Bean** 的对象自动标 `suspicious`
- **多 Context 支持**：自动遍历同 JVM 中的所有 Tomcat StandardContext
- **跨版本反射**：通过 `ReflectUtil` 处理 Tomcat 7-10、Spring 5.x/6.x 内部字段差异
- **报告原子写入**：写到 `<path>.tmp` 后 rename，避免 JVM 被中断时残留半写入文件

### v0.1 — 最小可用扫描（2026-05-18）

JVM 类枚举、Web 组件接口识别（Filter/Servlet/Listener/Valve/HandlerInterceptor）、稳定 Finding ID、JSON 报告。

## 架构

```text
memhunter-attach.jar          — 外部 CLI（JDK 11+）
memhunter-agent.jar           — Java Agent fat jar（JDK 8 字节码，含 Jackson + ASM 9.7）
memhunter-test-target.jar     — Spring Boot 2.7 测试应用
memhunter-test-target-injector — 模拟内存马注入器（仅测试用，**勿放生产**）
```

通信：`agentmain` 阻塞执行 + 报告原子写入到本地文件。不使用 Socket（避免容器网络隔离问题）。

### 包结构

```text
agent/src/main/java/com/memhunter/agent/
├── MemHunterAgent.java        # agentmain 入口，dispatch scan/clean/verify
├── AgentArgs.java             # CLI 参数解析 + 互斥校验
├── model/                     # Finding / ScanReport / CleanPlan / CleanResult / FilterBackup
├── report/                    # JsonReportWriter（原子写入）
├── scanner/
│   ├── ClassScanner / WebComponentDetector    # 类层面扫描
│   ├── tomcat/                                 # Tomcat Context 定位 + 4 类组件扫描
│   │   ├── StandardContextProvider 链
│   │   │   ├── MBeanContextProvider
│   │   │   └── ClassLoadedContextProvider (含 Thread-walk 兜底)
│   │   └── TomcatFilter/Servlet/Listener/ValveScanner
│   └── spring/                                 # Spring ApplicationContext 定位 + 2 类组件扫描
│       ├── ApplicationContextProvider 链
│       │   ├── DispatcherServletProvider
│       │   └── ServletContextAttrProvider
│       ├── SpringMappingScanner
│       └── SpringInterceptorScanner（locateContexts 公开供清理路径复用）
├── scoring/                   # 评分规则引擎 + 白名单 + 18 条 ScoringRule
│   ├── RuleEngine
│   ├── Whitelist
│   ├── baseline/              # BaselineIndex / BaselineLoader / BaselineNewRule
│   ├── bytecode/              # ASM-based BytecodeAnalyzer / BytecodeAnalysis 缓存
│   └── rules/
├── cleaner/                   # v0.6+ 清理子系统
│   ├── Cleaner（接口）+ AbstractCleaner（模板基类）
│   ├── AbstractTomcatCleaner / AbstractSpringCleaner
│   ├── TomcatFilter/Servlet/Listener/ValveCleaner
│   ├── SpringMapping/InterceptorCleaner
│   ├── CleanerRegistry（type → factory 路由，ContextKind 区分）
│   ├── RollbackStrategy（接口）+ 6 个 strategy 实现
│   ├── PlanReconciler（4 字段三方一致性闸门）
│   ├── EvidenceWriter / CleanPlanReader
│   └── Clean/Rollback Exceptions
└── verify/
    └── VerifyExecutor         # 独立 verify 命令

attach/src/main/java/com/memhunter/attach/
├── AttachMain                 # CLI 入口
├── AttachExecutor             # VirtualMachine attach
└── CleanInteractor            # stdin 严格 yes 确认
```

## Finding 类型表

| Finding type | 含义 | 关键 attributes |
|---|---|---|
| `class-filter` / `class-servlet` / `class-valve` / `class-interceptor` | 类层面发现（v0.1） | — |
| `class-listenerrequest` / `class-listenercontext` / `class-listenersession` | Listener 子类型（v0.2 细分） | — |
| `tomcat-filter` | StandardContext.filterDefs 注册的 Filter | filterClass, urlPatterns, dispatcherTypes, contextPath |
| `tomcat-servlet` | StandardContext.children 中的 Wrapper | servletClass, mappings, loadOnStartup, contextPath |
| `tomcat-listener-{request,session,context,other}` | applicationEventListeners + applicationLifecycleListeners | listenerKind, contextPath |
| `tomcat-valve` | Context Pipeline 中的 Valve | containerLevel, pipelineIndex, contextPath |
| `spring-mapping` | AbstractHandlerMethodMapping 注册的 mapping | pattern, methods, handlerMethod, beanName |
| `spring-interceptor` | AbstractHandlerMapping.adaptedInterceptors | order, includePatterns, excludePatterns |

## 评分规则参考

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

### runtime-only 判定

对每个 `tomcat-*` 和 `spring-*` finding，两链检查（任一命中即不标 runtime-only，维持 level=low）：

1. 类上是否有 `@WebFilter` / `@WebServlet` / `@WebListener` 注解（javax + jakarta 双命名空间）
2. 类是否在 Spring ApplicationContext 的 BeanDefinition 中

全部 miss → reasons 追加 `"runtime-only"`，level 从 `low` 升至 `suspicious`，score +3。

> v0.2 设计文档初版有第三链（web.xml 检查），但代码评审发现 ServletContext.getFilterRegistration() 对程序化注册的 Filter 也返回非 null（与 web.xml 注册无法区分），会让 v0.2 demo 用 `addFilter()` 注册的 FakeFilter 误判为合法。修复决定移除第三链。

## 端到端验证

启动 Spring Boot 测试目标后，注入器模块提供 4 个端点模拟内存马注入：

```bash
java -Djava.net.preferIPv4Stack=true -jar test-target/target/memhunter-test-target.jar &

curl http://localhost:8080/inject/filter             # 反射插入 FilterDef + FilterMap + ApplicationFilterConfig
curl http://localhost:8080/inject/servlet            # 反射创建 Wrapper 并 addChild + addServletMappingDecoded
curl http://localhost:8080/inject/listener           # 反射追加 applicationEventListeners
curl http://localhost:8080/inject/valve              # 反射插入 Context Pipeline
curl http://localhost:8080/inject/spring-mapping     # 反射 RequestMappingHandlerMapping.registerHandlerMethod
curl http://localhost:8080/inject/spring-interceptor # 直接 mutate adaptedInterceptors

PID=$(java -jar attach/target/memhunter-attach.jar list | grep memhunter-test-target | awk '{print $1}')
java -jar attach/target/memhunter-attach.jar $PID agent/target/memhunter-agent.jar scan
```

v0.7.1 真实 Tomcat E2E 清理流程证据归档在 `docs/superpowers/specs/v0.7.1-clean-flow-evidence/`，覆盖 4 类 Tomcat finding 的完整 dry-run → confirm → verify → before/after scan artifacts。

## 兼容性

| 组件 | 编译目标 | 运行环境 |
|---|---|---|
| attach | JDK 11+ 字节码 | JDK 11+ |
| agent | JDK 8 字节码 | 目标 JVM JDK 8 / 11 / 17 / 21 |
| test-target | JDK 8 字节码（Spring Boot 2.7） | JDK 8+ |

容器版本支持：Tomcat 7 / 8 / 9 / 10（含 Spring Boot 内嵌），Spring MVC 4.x / 5.x / 6.x。Spring cleaner 使用纯反射，无编译期 Spring 依赖。

### 已知环境 issue：JDK 17 + Windows 11 NIO Selector bug

某些 Windows 11 环境上 JDK 17 创建 NIO Selector 时 `UnixDomainSockets.connect0` 抛 `SocketException: Invalid argument: connect`，导致 Tomcat acceptor 启动失败。Workaround：用 JDK 8 启动 test-target。Agent JAR 仍是 JDK 8 字节码，可以 attach 到 JDK 8 / 11 / 17 / 21 任意目标 JVM。

### Tomcat Context 定位策略

- **MBeanContextProvider**：查询 `Catalina:type=Context,*` MBean → managedResource。Spring Boot 内嵌 Tomcat 默认不注册这些 MBean，此路径会返回空。
- **ClassLoadedContextProvider**：兜底链
  - WebappClassLoader → resources.context（标准 Tomcat 部署用）
  - Engine 静态字段扫描（少数老 Tomcat）
  - **Thread-walk 兜底**：扫描 `http-nio-*-Acceptor/Poller/exec-*` 线程的字段图，最深 12 层，找到 Engine 实例（Spring Boot 场景下唯一可靠路径）

### Spring ApplicationContext 定位策略

- **DispatcherServletProvider**：主路径，从 DispatcherServlet.webApplicationContext 反射读
- **ServletContextAttrProvider**：兜底，从 ServletContext attribute 中查 `WebApplicationContext.ROOT.SCOPE_HIERARCHY` 等键
- v0.8 起 `SpringScanner.locateContexts()` 已公开，清理路径与扫描路径复用同一定位逻辑

## 限制

**JDK 17+ 需要给 target JVM 加 `--add-opens`**（v0.9.1 起的已知限制）。
Agent 反射遍历 Thread/field graph 来定位 Tomcat `StandardEngine`，
JDK 9+ 的模块封装会阻止此反射，必须在启动 target 时加：

```
java --add-opens=java.base/java.lang=ALL-UNNAMED \
     --add-opens=java.base/java.lang.reflect=ALL-UNNAMED \
     --add-opens=java.base/java.util=ALL-UNNAMED \
     --add-opens=java.base/java.util.concurrent=ALL-UNNAMED \
     -jar your-app.jar
```

不加这些 flag，scanner 会退化到精度更差的 class-loaded 模式
（findings 形如 `class-filter` / `class-servlet`），cleaner 无法工作。
JDK 8 无模块系统，无需此 flag。

v0.8 **不包含**：

- WebFlux 应用（架构上目前不支持响应式栈）
- Spring Bean 清理（BeanDefinition / singletonObjects 移除，留 v0.9）
- HTML / Markdown 报告（仅 JSON）
- 多 Tomcat 版本系统化集成测试（依赖手动 E2E）
- 容器/K8s 环境下的进程发现自动化
- 完整路线图见 [`java_memshell_scanner_design.md`](java_memshell_scanner_design.md) §25

## 单元测试

```bash
cmd //c "mvnw.cmd -pl agent test"
```

v0.8 当前含 **214 个 agent 单元测试 + 12 个 attach 单元测试**（共 226 个），新增覆盖（相对 v0.7.1）：

- `AbstractCleaner` / `AbstractSpringCleaner` — 容器无关模板基类 + Spring 共享 helper
- `CleanerRegistry` — ContextKind 路由 + 6 cleaner defaultRegistry
- `SpringMappingCleaner` / `SpringInterceptorCleaner` — Phase A-E + 多 bean 副本替换 + rollback
- `MemHunterAgent` 双 context dispatch（dispatchForTest 3-arg seam）
- `CleanExecutionException.didMutate` 标志在 6 个 cleaner 中的精确传递

容器层 Scanner（TomcatScanner / SpringScanner / 各子 Scanner）通过端到端集成验证，未做单元测试（Tomcat/Spring 对象 mock 成本高）。

## 开发文档

设计文档：[`java_memshell_scanner_design.md`](java_memshell_scanner_design.md)（含 v0.1 ~ v1.0 全部里程碑）

| 版本 | 设计文档 | 实施计划 | 样例报告 / E2E 证据 |
|---|---|---|---|
| v0.1 | — | [v0.1 minimal-scan plan](docs/superpowers/plans/2026-05-18-v0.1-minimal-scan.md) | [v0.1 sample](docs/superpowers/specs/v0.1-sample-report.json) |
| v0.2 | [v0.2 container-scanning](docs/superpowers/specs/2026-05-19-v0.2-container-scanning-design.md) | [v0.2 plan](docs/superpowers/plans/2026-05-19-v0.2-container-scanning.md) | [v0.2 sample](docs/superpowers/specs/v0.2-sample-report.json) |
| v0.3 | [v0.3 scoring-rules](docs/superpowers/specs/2026-05-20-v0.3-scoring-rules-design.md) | [v0.3 plan](docs/superpowers/plans/2026-05-20-v0.3-scoring-rules.md) | [v0.3 sample](docs/superpowers/specs/v0.3-sample-report.json) |
| v0.4 | [v0.4 bytecode-scanning](docs/superpowers/specs/2026-05-21-v0.4-bytecode-scanning-design.md) | [v0.4 plan](docs/superpowers/plans/2026-05-21-v0.4-bytecode-scanning.md) | [v0.4 sample](docs/superpowers/specs/v0.4-sample-report.json) |
| v0.5 | [v0.5 baseline-comparison](docs/superpowers/specs/2026-05-21-v0.5-baseline-comparison-design.md) | [v0.5 plan](docs/superpowers/plans/2026-05-21-v0.5-baseline-comparison.md) | [clean baseline](docs/superpowers/specs/v0.5-clean-baseline.json) / [after inject](docs/superpowers/specs/v0.5-after-inject-report.json) |
| v0.6 | [v0.6 tomcat-filter-clean](docs/superpowers/specs/2026-05-22-v0.6-tomcat-filter-clean-design.md) | [v0.6 plan](docs/superpowers/plans/2026-05-22-v0.6-tomcat-filter-clean.md) | [v0.6 evidence](docs/superpowers/specs/v0.6-clean-flow-evidence/) |
| v0.6.1 | [v0.6.1 clean-audit-fixes](docs/superpowers/specs/2026-05-22-v0.6.1-clean-audit-fixes-design.md) | [v0.6.1 plan](docs/superpowers/plans/2026-05-22-v0.6.1-clean-audit-fixes.md) | — |
| v0.7 | [v0.7 tomcat-cleaners-extension](docs/superpowers/specs/2026-05-22-v0.7-tomcat-cleaners-extension-design.md) | [v0.7 plan](docs/superpowers/plans/2026-05-22-v0.7-tomcat-cleaners-extension.md) | — |
| v0.7.1 | — | — | [v0.7.1 4-类 E2E 证据](docs/superpowers/specs/v0.7.1-clean-flow-evidence/) |
| v0.8 | [v0.8 spring-cleaners](docs/superpowers/specs/2026-05-29-v0.8-spring-cleaners-design.md) | [v0.8 plan](docs/superpowers/plans/2026-05-29-v0.8-spring-cleaners.md) | — |
