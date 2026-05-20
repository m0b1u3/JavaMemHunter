# JavaMemHunter

Java 内存马扫描与清理工具（v0.2 — Tomcat / Spring 容器扫描 + runtime-only 评分）。

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
└── runtime/
    └── RuntimeOnlyDetector    # 注解 + Spring Bean 两链判定
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

v0.2 样例报告：[`docs/superpowers/specs/v0.2-sample-report.json`](docs/superpowers/specs/v0.2-sample-report.json) — 64 findings、21 个 runtime-only。其中 FakeFilter、FakeServlet、FakeInterceptor 全部被正确识别为 runtime-only suspicious。

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

v0.2 仍**不包含**（推迟到 v0.3+）：

- **runtime-only 误报较多**：Spring Boot 自动配置的正常组件（dispatcherServlet、各种 OrderedXxxFilter、HelloController 等）会被误标。根因：`RuntimeOnlyDetector.isSpringManaged` 用默认 ClassLoader `Class.forName()` 加载 Spring Boot fat jar 内的类失败。v0.3 用 ScanContext 传入正确 ClassLoader 修复。
- WebFlux 应用（不支持）
- 字节码扫描（关键字匹配、hash 计算）
- 白名单（包名/Agent/CodeSource）
- 基线对比
- 完整 17 条评分规则
- 清理操作
- HTML / Markdown 报告

完整路线图见 [`java_memshell_scanner_design.md`](java_memshell_scanner_design.md) 第 25 节。

## 单元测试

```bash
cmd //c "mvnw.cmd -pl agent test"
```

v0.2 含 29 个单元测试，新增覆盖：
- `ReflectUtil`（9）— 跨版本反射工具
- `WebComponentDetector`（6）— BFS 接口检测 + Listener 细分
- `AgentArgs`（4）— 未知选项告警
- `RuntimeOnlyDetector`（5）— 两链判定 + 4 种路径
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
