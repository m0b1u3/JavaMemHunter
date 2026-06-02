# Java 内存马扫描与清理工具设计文档

## 1. 文档信息

| 项目 | 内容 |
|---|---|
| 文档名称 | Java 内存马扫描与清理工具设计文档 |
| 项目代号 | memshell-scanner |
| 适用场景 | 应急响应、主机排查、Java Web 运行时安全检查、内存马取证与清理 |
| 目标环境 | Tomcat、Spring MVC、Spring Boot、部分兼容 Jetty / Undertow / WebLogic / WebSphere 的扩展架构 |
| 核心语言 | Java |
| 推荐 JDK | JDK 8 / 11 / 17 / 21 |
| 输出格式 | Console / JSON / HTML / Markdown |
| 默认模式 | 只读扫描 |
| 高危操作 | 清理运行时组件、注销 Spring Mapping、移除 Filter / Servlet / Listener / Valve |

---

## 2. 背景说明

Java 内存马通常不是传统落地文件型 WebShell，而是攻击者利用反序列化、JNDI 注入、表达式注入、后台命令执行、组件漏洞等入口，在 Java Web 容器或框架运行时动态注册恶意组件。

常见类型包括：

- Tomcat Filter 型内存马
- Tomcat Servlet 型内存马
- Tomcat Listener 型内存马
- Tomcat Valve 型内存马
- Spring Controller 型内存马
- Spring Interceptor 型内存马
- Java Agent / Instrumentation 型内存马
- ClassLoader / defineClass 动态加载型内存马
- WebSocket / Upgrade 协议型内存马
- 反射修改正常业务对象型内存马

传统文件查杀重点检查磁盘上的 JSP、JAR、CLASS 文件，但内存马可能只存在于 JVM 内存、Web 容器运行时注册表、Spring HandlerMapping、ClassLoader 已加载类中。因此需要一种能够进入目标 JVM 内部观察运行时状态的扫描工具。

---

## 3. 设计目标

### 3.1 核心目标

本工具目标是实现一个 Java 内存马扫描与清理工具，具备以下能力：

1. 发现目标 Java 进程中的异常运行时组件。
2. 枚举 JVM 已加载类并识别可疑类。
3. 枚举 Tomcat 运行时 Filter、Servlet、Listener、Valve。
4. 枚举 Spring MVC 运行时 Controller、HandlerMapping、Interceptor。
5. 对可疑对象进行评分并输出原因。
6. 导出 JSON / HTML / Markdown 报告。
7. 支持按对象 ID 精准清理，不做默认自动删除。
8. 清理前保存快照和证据。
9. 清理后自动复扫确认。
10. 支持后续扩展 Jetty、Undertow、WebLogic、WebSphere。

### 3.2 非目标

本工具不做以下事情：

1. 不生成内存马。
2. 不提供攻击载荷。
3. 不提供绕过安全产品的能力。
4. 不自动清空所有运行时组件。
5. 不默认修改业务类字节码。
6. 不替代完整主机应急响应，只作为 Java 运行时排查工具。

---

## 4. 总体架构

推荐采用双 JAR 架构：

```text
memshell-attach.jar      # 外部启动器，负责 attach 到目标 JVM
memshell-agent.jar       # Java Agent，被加载进目标 JVM 内部执行扫描和清理
```

### 4.1 Agent 通信机制

采用 **agentmain 阻塞执行 + 文件落盘** 方案：

- `agentmain` 在目标 JVM 内同步执行全部逻辑，执行完毕后退出，attach 端等待返回
- 扫描报告、证据文件、清理计划均写入本地文件系统
- attach 端通过 `VirtualMachine.loadAgent()` 传入命令参数，agent 解析后执行对应逻辑
- 不使用 Socket 通信，避免容器网络 namespace 隔离导致连接失败

clean 命令拆成两步执行，无需双向通信：

```text
第一步：clean --id <id> --dry-run   → 生成清理计划文件，人工审阅
第二步：clean --id <id> --confirm   → 读取计划文件，交互确认后执行
```

整体流程：

```text
安全人员执行命令
    ↓
memshell-attach.jar
    ↓
Attach 到目标 Java 进程 PID
    ↓
loadAgent 加载 memshell-agent.jar（传入命令参数）
    ↓
agentmain 在目标 JVM 内同步执行
    ↓
扫描 JVM / Tomcat / Spring / ClassLoader
    ↓
报告写入本地文件
    ↓
人工审阅报告
    ↓
dry-run 生成清理计划
    ↓
人工确认（终端输入 yes）
    ↓
按 ID 精准清理
    ↓
复扫验证
```

---

## 5. 工程目录设计

```text
memshell-scanner/
├── pom.xml
├── README.md
├── docs/
│   ├── design.md
│   ├── usage.md
│   └── risk-control.md
├── src/
│   └── main/
│       ├── java/
│       │   └── com/example/memshell/
│       │       ├── attach/
│       │       │   ├── AttachMain.java
│       │       │   ├── JvmProcessLister.java
│       │       │   └── AttachPermissionChecker.java
│       │       ├── agent/
│       │       │   ├── MemShellAgent.java
│       │       │   ├── AgentContext.java
│       │       │   └── AgentCommandDispatcher.java
│       │       ├── scanner/
│       │       │   ├── Scanner.java
│       │       │   ├── ClassScanner.java
│       │       │   ├── ClassLoaderScanner.java
│       │       │   ├── TomcatScanner.java
│       │       │   ├── SpringScanner.java
│       │       │   ├── ServletScanner.java
│       │       │   ├── ListenerScanner.java
│       │       │   ├── ValveScanner.java
│       │       │   └── InterceptorScanner.java
│       │       ├── cleaner/
│       │       │   ├── Cleaner.java
│       │       │   ├── CleanPlan.java
│       │       │   ├── TomcatCleaner.java
│       │       │   ├── SpringCleaner.java
│       │       │   └── RollbackManager.java
│       │       ├── detector/
│       │       │   ├── Finding.java
│       │       │   ├── FindingType.java
│       │       │   ├── RiskScore.java
│       │       │   ├── RuleEngine.java
│       │       │   ├── BytecodeKeywordRule.java
│       │       │   ├── CodeSourceRule.java
│       │       │   ├── ClassNameRule.java
│       │       │   ├── RuntimeRegistryRule.java
│       │       │   └── BaselineDiffRule.java
│       │       ├── report/
│       │       │   ├── Report.java
│       │       │   ├── JsonReportWriter.java
│       │       │   ├── HtmlReportWriter.java
│       │       │   └── MarkdownReportWriter.java
│       │       ├── snapshot/
│       │       │   ├── RuntimeSnapshot.java
│       │       │   ├── TomcatSnapshot.java
│       │       │   ├── SpringSnapshot.java
│       │       │   └── ClassSnapshot.java
│       │       └── util/
│       │           ├── ReflectUtil.java
│       │           ├── ClassUtil.java
│       │           ├── JsonUtil.java
│       │           ├── HashUtil.java
│       │           └── SafeExecutor.java
│       └── resources/
│           ├── META-INF/
│           │   └── MANIFEST.MF
│           ├── rules/
│           │   ├── default-rules.yml
│           │   └── whitelist.yml
│           └── templates/
│               └── report.html
└── target/
    ├── memshell-attach.jar
    └── memshell-agent.jar
```

---

## 6. 模块说明

### 6.1 attach 模块

负责从外部连接目标 JVM。

核心职责：

- 枚举当前机器 Java 进程。
- 根据 PID attach 到目标 JVM。
- 加载 agent JAR。
- 传入执行模式参数。
- 打印 attach 状态。
- 处理权限错误。

主要类：

```text
AttachMain
JvmProcessLister
AttachPermissionChecker
```

典型命令：

```bash
java -jar memshell-attach.jar <pid> ./memshell-agent.jar scan
```

---

### 6.2 agent 模块

Agent 模块是真正进入目标 JVM 内部执行逻辑的部分。

核心入口：

```java
public static void agentmain(String args, Instrumentation inst)
```

职责：

- 接收 attach-client 传入的命令。
- 初始化扫描上下文。
- 调用不同扫描器。
- 聚合扫描结果。
- 写出报告。
- 执行清理命令。
- 清理后复扫验证。

---

### 6.3 scanner 模块

负责采集运行时数据。

包括：

| 扫描器 | 作用 |
|---|---|
| ClassScanner | 扫描 JVM 已加载类 |
| ClassLoaderScanner | 扫描 ClassLoader 树 |
| TomcatScanner | 扫描 Tomcat StandardContext |
| ServletScanner | 扫描 Servlet / Wrapper |
| ListenerScanner | 扫描 Listener |
| ValveScanner | 扫描 Pipeline / Valve |
| SpringScanner | 扫描 Spring Mapping / Bean / Interceptor |
| InterceptorScanner | 扫描 Spring HandlerInterceptor |

---

### 6.4 detector 模块

负责把原始运行时对象转换成风险结果。

核心职责：

- 规则匹配。
- 风险评分。
- 原因解释。
- 白名单过滤。
- 基线对比。
- 输出 Finding 对象。

---

### 6.5 cleaner 模块

负责精准清理指定对象。

清理对象包括：

- Tomcat Filter
- Tomcat Servlet
- Tomcat Listener
- Tomcat Valve
- Spring Mapping
- Spring Interceptor
- Spring Bean
- 可疑 ClassFileTransformer

原则：

1. 默认不清理。
2. 必须指定 Finding ID。
3. 清理前导出证据。
4. 清理前生成 CleanPlan。
5. 清理后复扫。
6. 失败后尽量回滚。
7. 无法安全清理时只给出重启建议。

---

### 6.6 report 模块

负责输出报告。

支持格式：

- console
- JSON
- HTML
- Markdown

报告应包含：

- 目标进程信息
- JVM 信息
- 容器类型
- Spring 信息
- 扫描时间
- 可疑对象列表
- 风险评分
- 证据
- 清理建议
- 清理结果
- 复扫结果

---

## 7. 命令行设计

### 7.1 查看 Java 进程

```bash
java -jar memshell-attach.jar list
```

输出示例：

```text
PID     MainClass
12345   org.apache.catalina.startup.Bootstrap
22333   com.example.Application
```

---

### 7.2 只读扫描

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan
```

---

### 7.3 导出 JSON 报告

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --format json --output /tmp/memshell-report.json
```

---

### 7.4 导出 HTML 报告

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --format html --output /tmp/memshell-report.html
```

---

### 7.5 只扫描 Tomcat

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --target tomcat
```

---

### 7.6 只扫描 Spring

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --target spring
```

---

### 7.7 列出运行时组件

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar list-runtime
```

---

### 7.8 生成基线

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar baseline --output /opt/baseline/java-runtime-baseline.json
```

---

### 7.9 使用基线对比

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --baseline /opt/baseline/java-runtime-baseline.json
```

---

### 7.10 按 Finding ID 清理

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar clean --id finding-filter-a3f92c1d
```

---

### 7.11 清理后复扫

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar verify --id finding-filter-a3f92c1d
```

---

## 8. 扫描对象设计

### 8.1 JVM 已加载类

采集字段：

```json
{
  "className": "com.example.Abc",
  "classLoader": "org.apache.catalina.loader.ParallelWebappClassLoader",
  "codeSource": "file:/opt/tomcat/webapps/app/WEB-INF/classes/",
  "interfaces": [
    "javax.servlet.Filter"
  ],
  "superClass": "java.lang.Object",
  "hash": "sha256:xxxx",
  "suspiciousKeywords": [
    "java/lang/Runtime",
    "ProcessBuilder"
  ]
}
```

重点关注：

- 实现 Filter / Servlet / Listener / Valve / HandlerInterceptor 的类
- CodeSource 为空的类
- 来源在 `/tmp`、`/var/tmp`、上传目录中的类
- 类名随机
- ClassLoader 异常
- 字节码包含高危 API
- 非业务包名
- 非依赖白名单包名

---

### 8.2 Tomcat Filter

采集字段：

```json
{
  "type": "tomcat-filter",
  "filterName": "DebugFilter",
  "filterClass": "com.example.DebugFilter",
  "urlPatterns": ["/*"],
  "dispatcherTypes": ["REQUEST"],
  "codeSource": null,
  "classLoader": "WebappClassLoaderBase",
  "fromWebXml": false,
  "runtimeOnly": true
}
```

重点关注：

- runtimeOnly 为 true
- URL Pattern 为 `/*`
- filterName 随机
- filterClass 来源异常
- filter 排序靠前
- FilterConfig 存在但部署描述文件中不存在
- 字节码存在命令执行、反射、类加载、加解密特征

---

### 8.3 Tomcat Servlet

采集字段：

```json
{
  "type": "tomcat-servlet",
  "servletName": "ApiServlet",
  "servletClass": "com.example.ApiServlet",
  "mappings": ["/api/debug"],
  "loadOnStartup": -1,
  "codeSource": null,
  "runtimeOnly": true
}
```

重点关注：

- 源码中不存在的 Servlet Mapping
- 可疑路径
- 类来源为空
- Wrapper 动态创建
- `wasCreatedDynamicServlet` 相关线索

---

### 8.4 Tomcat Listener

采集字段：

```json
{
  "type": "tomcat-listener",
  "listenerClass": "com.example.ReqListener",
  "listenerObject": "com.example.ReqListener@1234",
  "listenerKind": "ServletRequestListener",
  "codeSource": null,
  "runtimeOnly": true
}
```

重点关注：

- ServletRequestListener
- HttpSessionListener
- ServletContextListener
- 动态添加但配置文件无记录
- Listener 中存在命令执行或反射逻辑

---

### 8.5 Tomcat Valve

采集字段：

```json
{
  "type": "tomcat-valve",
  "valveClass": "com.example.DebugValve",
  "containerLevel": "Context",
  "pipelineIndex": 0,
  "codeSource": null
}
```

重点关注：

- 非 Tomcat 默认 Valve
- 非 APM / 业务白名单 Valve
- CodeSource 为空
- 插入 Context / Host / Engine Pipeline
- 字节码存在高危 API

---

### 8.6 Spring Mapping

采集字段：

```json
{
  "type": "spring-mapping",
  "pattern": "/api/debug",
  "methods": ["GET", "POST"],
  "handlerClass": "com.example.DebugController",
  "handlerMethod": "run",
  "beanName": "debugController",
  "codeSource": null,
  "runtimeOnly": true
}
```

重点关注：

- HandlerMapping 中存在，但源码或基线中不存在
- Controller Bean 非正常包名
- HandlerMethod 所属类 CodeSource 为空
- Mapping 路径伪装
- Handler 方法内部存在高危 API

---

### 8.7 Spring Interceptor

采集字段：

```json
{
  "type": "spring-interceptor",
  "interceptorClass": "com.example.DebugInterceptor",
  "includePatterns": ["/*"],
  "excludePatterns": [],
  "codeSource": null,
  "runtimeOnly": true
}
```

重点关注：

- 匹配范围过大
- 动态添加
- 非业务包名
- CodeSource 为空
- preHandle 中存在高危 API

---

## 9. 风险评分设计

采用分值累计机制。

| 规则 | 分值 |
|---|---:|
| 实现 Filter / Servlet / Listener / Valve / HandlerInterceptor | +3 |
| CodeSource 为空 | +3 |
| CodeSource 位于临时目录 | +3 |
| 字节码包含 Runtime.exec / ProcessBuilder | +4 |
| 字节码包含 defineClass / ClassLoader#defineClass | +3 |
| 字节码包含 setAccessible / getDeclaredField | +2 |
| 字节码包含 Cipher / AES / Base64 | +2 |
| 运行时存在但 web.xml / 注解 / 基线不存在 | +4 |
| URL Pattern 为 `/*` | +2 |
| Filter 排序靠前 | +2 |
| 类名随机或高熵 | +1 |
| 非业务包名且非依赖白名单 | +2 |
| ClassLoader 异常 | +2 |
| Mapping 路径伪装成静态资源或健康检查 | +2 |
| 命中白名单 | -5 |
| 来源为已知 APM / 正常 Agent | -4 |

风险等级：

```text
0 - 3   低风险
4 - 6   可疑
7 - 9   高危
10+     严重
```

示例：

```json
{
  "id": "finding-filter-a3f92c1d",
  "type": "tomcat-filter",
  "name": "DebugFilter",
  "className": "com.example.Abc123",
  "score": 12,
  "level": "critical",
  "reasons": [
    "runtime only filter",
    "url pattern is /*",
    "codeSource is null",
    "bytecode contains ProcessBuilder"
  ]
}
```

---

## 10. 白名单设计

### 10.1 包名前缀白名单

```yaml
packageWhitelist:
  - "org.springframework."
  - "org.apache.catalina."
  - "org.apache.tomcat."
  - "org.apache.coyote."
  - "com.fasterxml.jackson."
  - "ch.qos.logback."
  - "org.slf4j."
  - "com.alibaba.druid."
```

### 10.2 业务包名白名单

```yaml
businessPackages:
  - "com.company."
  - "cn.company."
  - "com.example.app."
```

### 10.3 Agent 白名单

```yaml
agentWhitelist:
  - "arthas"
  - "skywalking"
  - "pinpoint"
  - "elastic-apm"
  - "opentelemetry"
  - "jrebel"
```

### 10.4 路径白名单

```yaml
codeSourceWhitelist:
  - "/opt/app/"
  - "/opt/tomcat/webapps/"
  - "/usr/local/tomcat/lib/"
```

---

## 11. 基线设计

### 11.1 为什么需要基线

很多正常 Java 应用也会动态生成类，例如：

- Spring CGLIB
- Hibernate Proxy
- MyBatis Mapper Proxy
- ByteBuddy
- JDK Proxy
- APM Agent
- Arthas
- JRebel

如果只依赖关键字，很容易误报。因此推荐在应用刚启动、确认干净时生成一份运行时基线。

### 11.2 基线内容

```json
{
  "app": "example-app",
  "pid": 12345,
  "time": "2026-05-18T15:00:00+09:00",
  "jvm": {
    "javaVersion": "17.0.10",
    "javaHome": "/usr/lib/jvm/java-17"
  },
  "tomcat": {
    "filters": [],
    "servlets": [],
    "listeners": [],
    "valves": []
  },
  "spring": {
    "mappings": [],
    "interceptors": [],
    "beans": []
  },
  "classes": []
}
```

### 11.3 基线对比

扫描时对比：

- 新增 Filter
- 新增 Servlet Mapping
- 新增 Listener
- 新增 Valve
- 新增 Spring Mapping
- 新增 Interceptor
- 新增可疑类
- 原有组件 className 变化
- 原有 class hash 变化

---

## 12. Tomcat 扫描设计

### 12.1 获取所有 StandardContext

一个 Tomcat 进程可以部署多个 Web 应用，每个应用对应一个独立的 StandardContext，拥有各自独立的 Filter、Servlet、Listener 注册表。扫描器必须枚举所有 Context，不能只扫描一个。

**推荐遍历路径：从 Engine 向下遍历**

```text
Server
  └── Service
        └── Engine
              └── Host（可能多个 Host）
                    └── StandardContext（可能多个 Context）
```

通过 MBeanServer 查询所有 `Catalina:type=Context` MBean，可获取所有已注册 Context 的引用：

```java
MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
Set<ObjectName> names = mbs.queryNames(new ObjectName("Catalina:type=Context,*"), null);
```

也可从已加载类中找到 `StandardEngine` 实例，递归遍历 `getChildren()`。

**多 Context 扫描原则：**

- 每个 Context 独立扫描，Finding ID 中包含 Context path 信息
- 报告按 Context 分组输出
- 基线生成时也按 Context 分组存储

可能路径（按优先级）：

1. MBeanServer 查询所有 Tomcat Context MBean（推荐，兼容性最好）
2. 从已加载类中找到 StandardEngine，递归 getChildren()
3. 从当前线程上下文 ClassLoader 反射获取 WebResourceRoot
4. 从 ServletContextFacade 反射获取 ApplicationContext，再获取 StandardContext
5. 从当前请求线程栈中定位容器对象

推荐实现多个 Provider：

```text
StandardContextProvider
├── MBeanContextProvider          # 主路径：MBeanServer 枚举所有 Context
├── EngineTraversalProvider       # 次要路径：从 Engine 递归遍历
├── ClassLoaderContextProvider
├── ServletContextProvider
└── ThreadStackContextProvider
```

### 12.2 扫描 Filter

采集来源：

- `StandardContext.findFilterDefs()`
- `StandardContext.findFilterMaps()`
- `StandardContext.findFilterConfig(name)`
- 反射读取 `filterConfigs`
- 反射读取 `filterDefs`
- 反射读取 `filterMaps`

输出：

- filterName
- filterClass
- urlPatterns
- dispatcherTypes
- initParameters
- filter instance class
- codeSource
- classLoader
- runtimeOnly
- score

### 12.3 扫描 Servlet

采集来源：

- `StandardContext.findChildren()`
- Wrapper
- servletClass
- servletName
- mappings
- loadOnStartup
- instance
- codeSource

### 12.4 扫描 Listener

采集来源：

- `applicationEventListeners`
- `applicationLifecycleListeners`
- `applicationListeners`
- Listener 实例对象
- Listener 类名

### 12.5 扫描 Valve

采集来源：

- `context.getPipeline()`
- `pipeline.getFirst()`
- `valve.getNext()`

需要识别：

- StandardContextValve
- ErrorReportValve
- AccessLogValve
- RemoteIpValve
- 自定义 Valve

---

## 13. Spring 扫描设计

### 13.1 获取 ApplicationContext

可能方式：

1. 从 WebApplicationContextUtils 获取。
2. 从 DispatcherServlet 获取 WebApplicationContext。
3. 从已加载 BeanFactory / ApplicationContext 静态引用中定位。
4. 从 Spring Boot Actuator 相关对象中定位。
5. 从当前 ClassLoader 和 ServletContext 中定位。

### 13.2 扫描 HandlerMapping

重点 Bean：

```text
RequestMappingHandlerMapping
BeanNameUrlHandlerMapping
SimpleUrlHandlerMapping
RouterFunctionMapping
WelcomePageHandlerMapping
```

主要关注：

- RequestMappingHandlerMapping#getHandlerMethods()
- AbstractHandlerMethodMapping#unregisterMapping()
- HandlerMethod#getBeanType()
- HandlerMethod#getMethod()

### 13.3 扫描 Interceptor

重点对象：

- AbstractHandlerMapping 的 adaptedInterceptors
- MappedInterceptor
- HandlerInterceptor
- WebMvcConfigurer 注册对象

采集字段：

- interceptorClass
- includePatterns
- excludePatterns
- order
- codeSource
- classLoader

### 13.4 扫描 Bean

关注：

- BeanDefinition 是否存在
- singletonObjects 中是否存在
- beanClassName 是否异常
- factoryBeanName 是否异常
- bean 来源是否为空
- 是否 runtime only

---

## 14. 字节码扫描设计

### 14.0 两阶段扫描策略

字节码扫描不对所有已加载类执行，而是分两阶段进行，避免在类数量庞大的应用中产生严重性能影响。

**第一阶段：初筛（无字节码读取）**

对所有已加载类按以下条件过滤，命中任意一条进入字节码精扫：

| 优先级 | 初筛条件 |
|---|---|
| 1 | 实现 Filter / Servlet / Listener / Valve / HandlerInterceptor |
| 2 | CodeSource 为空 |
| 3 | 运行时存在于容器注册表，但基线中不存在 |
| 4 | 类名高熵（随机字符，熵值超过阈值） |
| 5 | 非业务包名且非白名单包名 |

**第二阶段：字节码精扫**

仅对初筛命中的类读取字节码，执行关键字匹配和 hash 计算。

好处：
- 典型 Tomcat 应用加载数千个类，但真正可疑的通常只有几十个
- 扫描速度快，应急场景下可用
- 后续可通过 `--deep` 参数对全量类执行字节码扫描

### 14.1 字节码来源

可尝试从以下位置读取类字节码：

1. `clazz.getResourceAsStream("/a/b/C.class")`
2. CodeSource 文件路径
3. ClassLoader resource
4. Instrumentation transformer 临时 dump
5. 已知 class dump 工具扩展

### 14.2 关键字特征

高危关键字：

```text
java/lang/Runtime
getRuntime
exec
java/lang/ProcessBuilder
start
defineClass
getDeclaredField
getDeclaredMethod
setAccessible
javax/crypto/Cipher
java/util/Base64
sun/misc/BASE64Decoder
org/apache/catalina/core/StandardContext
org/springframework/web/servlet/mvc/method/annotation/RequestMappingHandlerMapping
```

注意：

- 单独命中 Base64 不代表恶意。
- 单独命中反射不代表恶意。
- 要结合 Web 组件类型、CodeSource、运行时注册表和基线对比。

### 14.3 Hash 设计

对类字节码计算：

- SHA-256
- MD5 可选，只用于兼容旧平台
- 文件路径 hash
- className hash

---

## 15. 清理设计

### 15.1 清理总原则

清理是高危操作，必须遵守：

1. 默认不执行清理。
2. 必须指定 Finding ID。
3. 必须先生成清理计划。
4. 必须先保存证据。
5. 必须支持 dry-run。
6. 必须执行后复扫。
7. 无法安全回滚时明确提示重启。
8. 不提供 clean-all 默认能力。

### 15.2 清理命令

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar clean --id finding-filter-a3f92c1d --dry-run
```

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar clean --id finding-filter-a3f92c1d --confirm
```

### 15.2.1 交互式二次确认流程

执行 `--confirm` 时，agent 将清理计划打印到终端，要求操作者明确输入 `yes` 后才真正执行：

```text
[!] You are about to clean:

    Type       : tomcat-filter
    Name       : DebugFilter
    Class      : com.example.Abc123
    Pattern    : /*
    Score      : 12
    Context    : /app

    Steps:
      1. backup filterDef / filterMap / filterConfig
      2. call filter.destroy()
      3. remove from filterConfigs / filterDefs / filterMaps
      4. re-scan to verify removal

    Rollback supported: YES

Type "yes" to confirm (anything else cancels):
```

输入非 `yes` 字符串时取消操作，不做任何修改。

此设计强制操作者在清理前完整阅读清理计划，防止手滑将错误 ID 与 `--confirm` 组合执行。

### 15.3 清理计划

```json
{
  "findingId": "finding-filter-a3f92c1d",
  "type": "tomcat-filter",
  "target": "DebugFilter",
  "steps": [
    "backup filterDef",
    "backup filterMap",
    "backup filterConfig",
    "call filter.destroy",
    "remove filterConfig",
    "remove filterDef",
    "remove filterMap",
    "verify filter not exists"
  ],
  "rollbackSupported": true
}
```

---

## 16. Tomcat 清理设计

### 16.1 Filter 清理

需要处理：

- filterConfigs
- filterDefs
- filterMaps
- Filter 实例 destroy
- URL Pattern 映射

清理步骤：

1. 根据 findingId 找到 filterName。
2. 导出 FilterConfig、FilterDef、FilterMap。
3. 调用 Filter.destroy()。
4. 从 filterConfigs 中移除。
5. 从 filterDefs 中移除。
6. 从 filterMaps 中移除对应映射。
7. 重新扫描确认不存在。
8. 如果失败，尝试恢复快照。

注意：

- 不同 Tomcat 版本 filterMaps 数据结构不同。
- Tomcat 8 / 9 / 10 的 javax / jakarta 包名不同。
- 如果对象结构不兼容，停止清理并建议重启。

### 16.2 Servlet 清理

需要处理：

- Wrapper
- servletMappings
- children
- 实例销毁
- mapping 删除

清理步骤：

1. 找到 Wrapper。
2. 导出 Wrapper 元数据。
3. 调用 unload / destroy。
4. 删除 servlet mapping。
5. 从 children 中移除 Wrapper。
6. 复扫。

### 16.3 Listener 清理

需要处理：

- applicationEventListeners
- applicationLifecycleListeners
- applicationListeners

清理步骤：

1. 定位 Listener 实例。
2. 判断 Listener 类型。
3. 从数组或列表中移除。
4. 复扫。

### 16.4 Valve 清理

需要处理：

- Pipeline
- Valve 链表

清理步骤：

1. 定位目标 Valve。
2. 保存前后 Valve 链关系。
3. 从 Pipeline 移除。
4. 复扫。

---

## 17. Spring 清理设计

### 17.1 Mapping 清理

Spring MVC 可以通过 HandlerMapping 注销 mapping。

清理步骤：

1. 找到 RequestMappingHandlerMapping。
2. 根据 pattern / methods / handlerMethod 找到 RequestMappingInfo。
3. 调用 unregisterMapping。
4. 复扫确认 Mapping 消失。
5. 如果对应 Bean 也是 runtime only，进入 Bean 清理流程。

### 17.2 Interceptor 清理

清理对象：

- MappedInterceptor
- HandlerInterceptor
- adaptedInterceptors
- mappedInterceptors

步骤：

1. 找到对应 interceptor 实例。
2. 保存列表快照。
3. 从列表中移除。
4. 复扫。

### 17.3 Bean 清理

清理对象：

- BeanDefinition
- singletonObjects
- earlySingletonObjects
- singletonFactories
- disposableBeans

步骤：

1. 判断是否 runtime only。
2. 判断是否仍被 Mapping 或 Interceptor 引用。
3. 销毁 Bean。
4. 从 BeanFactory 中移除。
5. 复扫。

---

## 18. 证据导出设计

清理前必须导出：

```text
evidence/
├── finding-filter-a3f92c1d/
│   ├── finding.json
│   ├── class-info.json
│   ├── bytecode.bin
│   ├── bytecode.sha256
│   ├── runtime-object.json
│   ├── clean-plan.json
│   └── before-snapshot.json
```

证据内容：

- 类名
- CodeSource
- ClassLoader
- URL Pattern
- Handler Mapping
- 字节码 hash
- 可疑关键字
- 运行时对象摘要
- 清理前快照

---

## 19. 报告格式设计

### 19.1 JSON 报告

```json
{
  "scanId": "scan-20260518-150000",
  "target": {
    "pid": 12345,
    "mainClass": "org.apache.catalina.startup.Bootstrap",
    "javaVersion": "17.0.10",
    "os": "Linux"
  },
  "summary": {
    "totalFindings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  },
  "findings": [
    {
      "id": "finding-filter-a3f92c1d",
      "type": "tomcat-filter",
      "level": "critical",
      "score": 12,
      "name": "DebugFilter",
      "className": "com.example.Abc123",
      "reasons": [
        "runtime only filter",
        "codeSource is null",
        "urlPattern is /*"
      ],
      "recommendation": "manual confirm then clean by id"
    }
  ]
}
```

### 19.2 Console 报告

```text
[+] Scan finished
PID: 12345
Container: Tomcat 9.x
Spring: detected

[CRITICAL] finding-filter-a3f92c1d
Type: tomcat-filter
Name: DebugFilter
Class: com.example.Abc123
Pattern: /*
Score: 12
Reason:
 - runtime only filter
 - codeSource is null
 - bytecode contains ProcessBuilder
Action:
 - run clean --id finding-filter-a3f92c1d --dry-run first
```

---

## 20. 安全策略

### 20.1 默认安全行为

默认只读扫描：

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan
```

禁止默认清理。

### 20.2 清理保护

清理必须满足：

- 指定 ID。
- 风险等级至少 high。
- 用户传入 `--confirm`。
- 清理前成功保存证据。
- 清理计划生成成功。
- 目标对象当前仍存在。

### 20.3 禁止操作

工具不提供：

```text
clean-all
delete-all-filter
delete-all-mapping
remove-all-listener
force-clear-context
```

如需强制模式，必须隐藏在开发配置中，并默认禁用。

---

## 21. 运行时安全与特殊场景

### 21.1 清理并发安全

清理 Filter / Valve / Interceptor 时，目标 JVM 可能正在处理并发请求，直接从注册表中移除对象可能导致正在执行 filter chain 的线程出现 NPE 或 ConcurrentModificationException。

处理策略：

- **不在清理时主动等待请求排空**（应急场景下不可预期）
- **清理操作使用原子性替换**：先构造新的 filterConfigs / filterMaps 副本，移除目标对象后通过反射一次性替换，减小并发窗口
- **清理后在报告中提示**：如果应用负载较高，建议在低峰期执行清理或在清理后重启服务以彻底消除风险
- **不提供锁定请求处理的能力**：强行暂停 Tomcat 线程池超出工具职责范围

### 21.2 Agent 类残留风险

`agentmain` 执行完毕后，agent JAR 中的类仍然留在目标 JVM 的 ClassLoader 中。对长期运行的应用多次 attach 会持续累积类。

处理策略：

- agent 内部类尽量精简，不持有静态状态，减少内存占用
- agentmain 执行完毕前主动将所有静态引用置 null，触发 GC
- 在文档和 README 中明确说明：不建议对同一进程频繁 attach，生产环境排查完毕后建议在维护窗口重启服务
- 不提供 agent 卸载能力（JVM 不支持动态卸载 agent）

### 21.3 Spring Boot fat jar 场景

Spring Boot 内嵌 Tomcat 的 ClassLoader 结构与独立 Tomcat 不同：

| 差异点 | 标准 Tomcat | Spring Boot fat jar |
|---|---|---|
| ClassLoader | WebappClassLoaderBase | LaunchedURLClassLoader |
| CodeSource | 指向 webapps 目录 | 指向 fat jar 内部路径（`jar:file:/app.jar!/BOOT-INF/...`） |
| Context 获取 | MBeanServer 或 Engine 遍历 | 优先从 DispatcherServlet 或 SpringApplication 获取 EmbeddedWebApplicationContext |

扫描器在判断 CodeSource 是否可信时，需要识别 fat jar 内部路径格式，不能将 `jar:file:/...` 路径误判为异常来源。

白名单中需要增加 fat jar 路径模式：

```yaml
codeSourceWhitelist:
  - "/opt/app/"
  - "/opt/tomcat/webapps/"
  - "/usr/local/tomcat/lib/"
  - "jar:file:"          # Spring Boot fat jar 内部路径前缀
```

获取 ApplicationContext 时，优先从 `SpringApplication` 静态引用或 `EmbeddedWebApplicationContext` 入手，而不是依赖 `WebApplicationContextUtils`（后者在内嵌容器场景下可能无法直接使用）。

---

## 22. 兼容性设计

### 21.1 JDK 兼容

| JDK | 支持情况 | 注意事项 |
|---|---|---|
| JDK 8 | 支持 | 需要 tools.jar |
| JDK 11 | 支持 | Attach API 位于 jdk.attach 模块 |
| JDK 17 | 支持 | 模块访问限制更严格，需动态注入 --add-opens |
| JDK 21 | 支持 | 动态 Agent 加载默认警告，需 -XX:+EnableDynamicAgentLoading 或接受警告 |
| JRE-only | 不推荐 | 可能无法 attach |

### 21.1.1 JDK 17 / 21 反射限制处理

JDK 17+ 对反射访问私有字段有严格限制，直接调用 `setAccessible(true)` 会抛出 `InaccessibleObjectException`。扫描器大量依赖反射读取 `filterConfigs`、`filterDefs`、`applicationEventListeners` 等私有字段，必须处理此问题。

**处理策略：两层降级**

**第一层：Agent 加载时动态注入 `--add-opens`**

`agentmain` 入口处通过 Instrumentation 和反射调用 `jdk.internal.misc.Unsafe` 或直接操作模块系统，动态为必要包添加 `--add-opens`，无需修改目标进程启动参数：

```text
需要开放的模块：
--add-opens java.base/java.lang=ALL-UNNAMED
--add-opens java.base/java.util=ALL-UNNAMED
--add-opens java.base/java.lang.reflect=ALL-UNNAMED
--add-opens java.management/sun.management=ALL-UNNAMED
```

具体实现参考 Arthas 的 `ModuleUtils` 做法，通过 `Instrumentation.redefineModule()` 动态添加 opens。

**第二层：MBean / 公开 API 兜底**

动态注入失败，或特定字段在当前 JDK 版本不可访问时，降级走 MBeanServer 查询：

```text
反射路径失败 → MBeanServer 查询 Tomcat Context MBean
                → 通过公开 API（findFilterDefs / findChildren）获取部分信息
                → 在报告中标记 partial_scan，说明受限字段
```

原则：局部反射失败不阻断整体扫描，只影响该字段的采集完整性。

### 21.2 Servlet 包名兼容

| 版本 | 包名 |
|---|---|
| Tomcat 7 / 8 / 9 | javax.servlet |
| Tomcat 10 / 11 | jakarta.servlet |

扫描器需要同时识别：

```text
javax.servlet.Filter
jakarta.servlet.Filter
javax.servlet.Servlet
jakarta.servlet.Servlet
javax.servlet.ServletRequestListener
jakarta.servlet.ServletRequestListener
```

### 21.3 容器兼容

| 容器 | 第一阶段 |
|---|---|
| Tomcat | 完整支持 |
| Spring Boot 内嵌 Tomcat | 完整支持 |
| Jetty | 预留扩展 |
| Undertow | 预留扩展 |
| WebLogic | 预留扩展 |
| WebSphere | 预留扩展 |

---

## 22. 异常处理设计

常见错误：

### 22.1 Attach 失败

原因：

- 权限不足
- 目标 JVM 禁用 attach
- 不是同一用户
- 容器 namespace 隔离
- JDK 不完整
- `/tmp/.java_pid<PID>` 不可访问

处理：

- 输出原因。
- 提示使用同用户或 root。
- 提示检查 JDK。
- 提示容器场景需进入同 namespace。

### 22.2 Agent 加载失败

原因：

- Manifest 缺少 Agent-Class
- agentmain 方法不存在
- JDK 版本不兼容
- 模块访问限制

处理：

- 输出具体异常。
- 提示检查 Manifest。
- 提示加 `--add-opens` 或使用对应 JDK。

### 22.3 扫描失败

原因：

- 容器版本不兼容
- 反射字段不存在
- SecurityManager 限制
- ClassLoader 隔离

处理：

- 局部失败不影响整体扫描。
- 每个 scanner 独立 try-catch。
- 报告中记录 unsupported reason。

### 22.4 清理失败

原因：

- 对象已不存在
- 对象结构不兼容
- 清理中业务正在访问
- 无法安全修改内部结构

处理：

- 停止后续步骤。
- 输出失败步骤。
- 尝试回滚。
- 建议重启服务。

---

## 23. 配置文件设计

`rules/default-rules.yml`：

```yaml
risk:
  critical: 10
  high: 7
  suspicious: 4

keywords:
  command:
    - "java/lang/Runtime"
    - "getRuntime"
    - "exec"
    - "java/lang/ProcessBuilder"
  classloader:
    - "defineClass"
    - "ClassLoader"
  reflection:
    - "getDeclaredField"
    - "getDeclaredMethod"
    - "setAccessible"
  crypto:
    - "javax/crypto/Cipher"
    - "java/util/Base64"

runtime:
  suspiciousUrlPatterns:
    - "/*"
    - "/favicon.ico"
    - "/health"
    - "/actuator/health"
    - "/static/*"
```

`rules/whitelist.yml`：

```yaml
businessPackages:
  - "com.company."
  - "cn.company."

trustedCodeSource:
  - "/opt/app/"
  - "/opt/tomcat/webapps/"
  - "/usr/local/tomcat/lib/"

trustedAgents:
  - "arthas"
  - "skywalking"
  - "opentelemetry"
  - "pinpoint"
```

---

## 24. 数据模型设计

### 24.1 Finding

Finding ID 采用**对象特征 hash** 生成，格式为 `finding-<type>-<hash8位>`。

hash 输入字段：`type + className + urlPattern/mappingPath`，对这三个字段拼接后取 SHA-256 前 8 位（十六进制）。

好处：
- 同一个内存马跨多次扫描 ID 保持不变，clean 命令中的 ID 可直接复用
- 清理后复扫时，能通过 ID 缺失直接确认对象已消失
- 基线对比时，新增 Finding 意味着新 ID 出现

示例：`finding-filter-a3f92c1d`、`finding-spring-mapping-b71e04ca`

```java
public class Finding {
    private String id;          // finding-<type>-<sha256前8位>
    private String type;
    private String level;
    private int score;
    private String name;
    private String className;
    private String codeSource;
    private String classLoader;
    private List<String> reasons;
    private Map<String, Object> evidence;
    private String recommendation;
}
```

### 24.2 RuntimeComponent

```java
public class RuntimeComponent {
    private String type;
    private String name;
    private String className;
    private Object runtimeObject;
    private String codeSource;
    private String classLoader;
    private Map<String, Object> attributes;
}
```

### 24.3 CleanPlan

```java
public class CleanPlan {
    private String findingId;
    private String componentType;
    private String targetName;
    private List<String> steps;
    private boolean rollbackSupported;
    private Map<String, Object> backup;
}
```

---

## 25. 开发里程碑

### v0.1：最小可用扫描（已完成）

目标：

- Attach 到目标 JVM
- Agent 加载成功
- 枚举已加载类
- 识别 Web 组件接口
- 输出 className / CodeSource / ClassLoader
- JSON 报告

### v0.2：Tomcat 扫描（已完成 — 含 Spring HandlerMapping/Interceptor + runtime-only 评分）

目标：

- 定位 StandardContext
- 枚举 Filter
- 枚举 Servlet
- 枚举 Listener
- 枚举 Valve
- 输出风险评分

### v0.3：评分规则引擎与白名单（已完成）

目标：

- 12 条评分规则统一接管 score/level/reasons
- 内置 framework / APM / CodeSource 白名单
- 支持 `--whitelist <file>` 用户追加白名单
- 支持 `--explain` 输出 ruleHits
- 将 FakeFilter / FakeServlet / FakeInterceptor 升至 high/critical
- 将 WsFilter / StandardContextValve 等框架组件降回 low

### v0.4：字节码规则接入（已完成）

目标：

- 字节码扫描规则接入现有 ScoringRule
- ASM 9.7 读取目标类字节码
- 5 条字节码评分规则接入现有 ScoringRule
- FakeFilter / FakeServlet / FakeInterceptor 注入项全部提升到 critical

### v0.5：基线对比（已完成）

目标：

- 复用 ScanReport JSON 作为基线文件
- 支持 `scan --baseline <file>`
- 新增 `baseline-new` 评分规则（+4）
- Summary 输出 `baselineNewCount` / `baselineMatchedCount`
- Listener / Interceptor Finding ID 跨 JVM 重启稳定
- 归档 v0.5 干净基线和注入后 E2E 样例报告

### v0.6：安全清理（已完成 — Tomcat Filter dry-run / confirm / verify）

目标：

- 清理 Tomcat Filter（已完成）
- dry-run 生成清理计划与证据包（已完成）
- confirm 严格二次确认后执行清理（已完成）
- 清理前快照与清理结果落盘（已完成）
- 清理后复扫与 verify-result 输出（已完成）
- Tomcat Servlet / Listener / Valve 清理（后续版本）
- Spring Mapping / Interceptor 清理（后续版本）

v0.6 E2E 证据已归档到 `docs/superpowers/specs/v0.6-clean-flow-evidence/`。在 FakeFilter 注入场景中，清理前 finding 为 `critical`，执行 `clean --confirm` 后 `clean-result.success=true`、`verifiedDisappeared=true`，随后 `verify --id` 输出 `stillPresent=false`。

### v0.6.1：Clean 流程审计链修复（已完成）

目标：

- confirm 阶段强制比对持久化 plan 与新生成 plan（findingId/filterClass/score/forced）
- --force 三方一致性校验（persisted ≡ fresh ≡ confirmFlag）
- Phase D 步骤标签区分 destroy-ran / no-release-method / destroy-threw
- 新增 EXIT_PLAN_STALE=3 退出码
- 新增 PlanReconciler + PlanStaleException

### v0.7：Tomcat Cleaners 扩展（已完成）

目标：

- 新增 TomcatServletCleaner / TomcatListenerCleaner / TomcatValveCleaner
- CleanPlan schema 抽象：targetName/targetClass + details
- CleanerRegistry：type 到 Cleaner factory 查表（exact + prefix 匹配）
- AbstractTomcatCleaner：共享 Phase A/D/E 模板
- RollbackStrategy 接口：替换单一 RollbackManager；每个 Cleaner 自带 strategy
- PlanReconciler：filterClass → targetClass 字段重命名
- MemHunterAgent：polymorphic dispatch via CleanerRegistry
- 197 单元/集成测试覆盖 4 类 Cleaner 全 Phase + dispatch + 旧 v0.6 plan 拒绝

### v0.8：Spring Cleaners 扩展（已完成）

目标：

- 新增 SpringMappingCleaner（官方 unregisterMapping）/ SpringInterceptorCleaner
  （adaptedInterceptors 副本替换）
- 提取容器无关的 AbstractCleaner；AbstractTomcatCleaner / AbstractSpringCleaner
  继承它
- CleanerRegistry：ContextKind 路由（TOMCAT / SPRING）
- MemHunterAgent：dual-context dispatch（同时定位 Tomcat StandardContext +
  Spring ApplicationContext）
- CleanExecutionException.didMutate：精确 rolledBack 标志（修 v0.7 Valve nit）
- 单元/集成测试覆盖两类 Spring Cleaner 全 Phase + dispatch

### v0.8.1：E2E evidence 归档 + FakeValve JDK 17 兼容修复（已完成）

目标：

- 真实 test-target 跑通 6 类内存马清理 E2E（filter / servlet / listener / valve
  / spring-mapping / spring-interceptor），证据归档到
  `docs/superpowers/specs/v0.8-clean-flow-evidence/`
- FakeValveInjector 在 JDK 17 下 setAccessible(true) 修复（catalina 包模块封装
  导致 public 方法仍需 setAccessible 才能反射调用）
- 发现并记录两个 v0.8.2 patch 候选：
  1. `--force` 不能与 `--dry-run` 组合 → sub-threshold finding 无法生成
     evidence bundle
  2. `clean --confirm` 在 plan 文件不存在时仍执行清理 → PlanReconciler 审计
     链有后门

### v0.8.2：Audit-Chain 修复（已完成）

目标：

- 修复 VerifyExecutor 只扫 Filter 假阴性 bug（抽 FindingLocator；VerifyExecutor
  接受双 context，覆盖全部 6 类 finding）
- 删除 AgentArgs.validate 中阻断 dry-run --force 的 force-gate（一致性已由 v0.6.1
  PlanReconciler 三方一致性保证）
- AttachMain 在 confirm 时若 plan 文件不存在 → 友好 stderr + 退出码 2，不触达 agent
- 新增 FindingLocator 单测（4 个），VerifyExecutor 单测扩展到 Spring 类型，
  AttachMain 单测覆盖 plan-missing 路径

### v0.9：多版本兼容 + 开源准备（已完成）

目标：

- 同一份 agent.jar 同时支持 Spring Boot 2.7 + Tomcat 9 + javax 与 Spring Boot 3.2 +
  Tomcat 10 + jakarta；新增 `ServletApiBridge` 抽象 javax/jakarta servlet API
- 4 处 scanner / 规则字符串字面量列表镜像 jakarta 命名（DefaultWhitelist、
  WebComponentDetector、TomcatListenerScanner、RuntimeOnlyRule —— 此前迭代已
  接近完成，本期确认并扩展单测覆盖）
- 新增 `test-target-sb32` + `test-target-injector-sb32` 模块（Spring Boot 3.2 +
  jakarta + JDK 17 编译目标）
- 新增 `integration-tests` 模块，sb27 / sb32 双 Maven profile，通过
  ProcessBuilder fork attach.jar 子进程驱动真实 attach 流程，覆盖 6 finding
  type × scan / clean / verify 完整 E2E
- 新增 `.github/workflows/test.yml`（unit + sb27/sb32 矩阵）与 `release.yml`
  （tag v* 触发，上传 memhunter-agent.jar + memhunter-attach.jar）
- 新增 Apache 2.0 LICENSE、CONTRIBUTING.md、Issue/PR 模板
- README 拆为双语：英文 README.md 作为入口，中文 README.zh-CN.md 作为详细文档
- 补 v0.1 → v0.8.2 共 12 个历史 release tag，v0.9 为首个走 release.yml 自动
  打包的官方 release
- 参考：`docs/superpowers/specs/2026-06-01-v0.9-multiversion-opensource-design.md`、
  `docs/superpowers/plans/2026-06-01-v0.9-multiversion-opensource.md`

### v0.10：Agent 型内存马检测 + 误报降低（已完成）

目标：

- 新增 `AgentTypeScanner`（com.memhunter.agent.scanner.agent），聚合三个子检测器：
  - `TransformerScanner`：反射 `InstrumentationImpl.mTransformerManager.mTransformers`
    扫已注册的 `ClassFileTransformer`，非白名单的 → finding `agent-transformer`
    （high, score=10）。白名单含 com.memhunter. 自身 + 9 个主流 APM 前缀
    （Skywalking/Arthas/Pinpoint/Byte-buddy/Jacoco/Elastic APM/NewRelic/
    Dynatrace/OpenTelemetry）
  - `DynamicClassScanner`：扫所有已加载类，找 codeSource==null 且
    （classLoader 非标准 OR 短类名）的类 → finding `agent-dynamic-class`
    （suspicious, score=4）
  - `BytecodeTamperScanner`：对 5 个关键类（ApplicationFilterChain、
    StandardContextValve、CoyoteAdapter、HttpServlet、DispatcherServlet）做
    内存字节码（retransformClasses 捕获）vs JAR 字节码（getResourceAsStream）
    对比，不一致 → finding `agent-bytecode-tampered`（critical, score=15）。
    捕获用临时 transformer + finally removeTransformer，不污染目标 JVM
- `RuleEngine.evaluateOne` 对 `agent-*` 型 finding 早返回，保留 scanner 设置的
  权威固定分数（不被规则集重算降级）
- 误报降低：`TomcatServletScanner` 调用
  `StandardContext.wasCreatedDynamicServlet(servlet)`、`TomcatFilterScanner`
  读 `FilterDef.dynamic` 字段，给 finding 打 `isDynamic` 属性。
  `RuntimeOnlyRule` 对 `isDynamic=false`（web.xml 静态声明）早返回，
  消除 Tomcat examples（HelloWorldExample/async0~3 等）的大量误报
- `ReflectUtil.tryInvokeWithArg` 新增单参数方法调用重载（continue on
  setAccessible failure，遍历类层级）
- 实测背景：冰蝎 AgentNoFile 在 JDK 8 + Windows 注入失败（pointerLength 字段
  缺失），但本期检测能力覆盖注入成功的场景
- 参考：`docs/superpowers/specs/2026-06-02-v0.10-agent-type-scanner-design.md`、
  `docs/superpowers/plans/2026-06-02-v0.10-agent-type-scanner.md`

### v0.10.1：真实环境复测修复（已完成）

在真实独立 Tomcat 9.0.94 + JDK 8 上用真实手法（JSP 从请求线程反射注册 Filter
内存马到 ROOT webapp、后门可执行命令）实测，暴露并修复 4 个真实问题：

- **多 webapp 检测盲区（漏报核心威胁）**：`ClassLoadedContextProvider`
  原先在 WebappClassLoader 策略找到任意一个 context 后就提前 return，从不执行
  Engine→Host→Context 完整遍历。实测只定位到 /examples 一个，注入到 ROOT 的
  ShellFilter 完全漏报。修复：两个策略都跑、seen 去重；并在 `looksLikeTomcatThread`
  加入 `Catalina`（独立 Tomcat 刚启动时 StandardEngine 仅通过 Catalina-utility-N
  线程可达）。修复后定位到全部 5 个 webapp context，ShellFilter 被检出为
  tomcat-filter / critical。
- **BytecodeTamperScanner 100% 误报**：逐字节 `Arrays.equals` 比对内存 vs JAR
  字节码，常量池/debug/属性顺序的良性差异导致 4 个关键类全报 critical（memSize
  == diskSize 却 byte 不等）。修复：改用 ASM 提取每方法的操作码指纹
  （SKIP_DEBUG|SKIP_FRAMES），只在方法增/删/方法体改时报告。误报清零。
- **attach.jar 无法在 JDK 8 运行**：attach 模块编译为 Java 11 字节码（class v55），
  在 JDK 8 上跑报 UnsupportedClassVersionError——而 JDK 8 是主流生产 Tomcat 运行时。
  修复：attach 改用 source/target 8（非 release，否则会隐藏 com.sun.tools.attach）
  产出 Java 8 字节码，一份 attach.jar 既能在 JDK 8（带 tools.jar）也能在 JDK 9+ 运行。
- 附带发现并记录：用不匹配的 JDK 版本 attach 一次会污染目标 JVM 的 attach 通道，
  后续正确版本也连不上，只能重启目标 JVM 恢复（应急取证注意事项）。

### v1.0：生产可用

目标：

- 多版本 Tomcat 适配
- Spring Boot 适配
- 容器环境适配
- 错误处理完善
- 报告模板完善
- 单元测试和集成测试
- README 和操作手册

---

## 26. 测试方案

### 26.1 单元测试

测试内容：

- 风险评分规则
- 白名单规则
- JSON 报告生成
- ReflectUtil 字段读取
- HashUtil
- CleanPlan 生成

### 26.2 集成测试

测试环境：

- Tomcat 8
- Tomcat 9
- Tomcat 10
- Spring Boot 2
- Spring Boot 3
- JDK 8
- JDK 11
- JDK 17
- JDK 21

测试场景：

- 正常业务应用，无内存马。
- 存在动态 Filter。
- 存在动态 Servlet。
- 存在动态 Listener。
- 存在动态 Valve。
- 存在动态 Spring Mapping。
- 存在动态 Interceptor。
- 存在正常 APM Agent。
- 存在 Arthas。
- 存在 CGLIB / ByteBuddy 正常代理类。

### 26.3 清理测试

测试内容：

- 清理前快照是否生成。
- dry-run 是否不修改对象。
- 清理指定 Filter 后是否不可访问。
- 清理指定 Mapping 后是否不可访问。
- 清理失败是否停止。
- 回滚是否恢复对象。
- 清理后复扫是否确认消失。

---

## 27. 部署和使用流程

### 27.1 编译

```bash
mvn clean package
```

输出：

```text
target/memshell-attach.jar
target/memshell-agent.jar
```

### 27.2 查看 Java 进程

```bash
jps -lv
```

或：

```bash
java -jar memshell-attach.jar list
```

### 27.3 执行扫描

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --format json --output /tmp/report.json
```

### 27.4 查看报告

```bash
cat /tmp/report.json
```

### 27.5 清理前 dry-run

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar clean --id finding-filter-a3f92c1d --dry-run
```

### 27.6 确认清理

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar clean --id finding-filter-a3f92c1d --confirm
```

### 27.7 清理后复扫

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --format json --output /tmp/report-after.json
```

---

## 28. 风险和限制

### 28.1 误报风险

可能误报对象：

- Spring CGLIB 代理
- Hibernate Proxy
- MyBatis Mapper Proxy
- ByteBuddy 动态类
- APM Agent
- Arthas
- JRebel
- SkyWalking
- OpenTelemetry

解决方式：

- 业务包名白名单
- CodeSource 白名单
- Agent 白名单
- 基线对比
- 多特征评分，不单点判断

### 28.2 漏报风险

可能漏报场景：

- 恶意逻辑嵌入正常业务类
- 字节码被动态修改但类名不变
- 恶意逻辑只在特定条件触发
- Agent 型内存马隐藏 transformer
- 容器对象结构不兼容导致未扫描到

缓解方式：

- 增加 transformer 扫描
- 增加类 hash 基线
- 增加线程栈扫描
- 增加 JMX/MBean 扫描
- 增加请求链对比
- 增加业务源码路由对比

### 28.3 清理风险

可能影响：

- 删除正常 Filter 导致鉴权失效
- 删除正常 Interceptor 导致业务异常
- 修改容器内部结构导致请求异常
- 清理时并发请求触发异常
- 无法完全回滚

处理策略：

- 默认只读
- dry-run
- 指定 ID 清理
- 清理前快照
- 非兼容对象不清理
- 生产环境优先建议重启服务

---

## 29. 后续增强方向

1. 支持 Jetty Handler / Filter / Servlet 扫描。
2. 支持 Undertow Handler 链扫描。
3. 支持 WebLogic Filter / Servlet / WorkContext 相关排查。
4. 支持 WebSphere 特定容器对象扫描。
5. 支持线程栈可疑行为分析。
6. 支持 ClassFileTransformer 枚举。
7. 支持已加载类 dump。
8. 支持与 EDR / SIEM 对接。
9. 支持远程 Agent 管理。
10. 支持 Web 控制台。
11. 支持扫描报告差异对比。
12. 支持容器 Kubernetes 场景自动进入 namespace。
13. 支持 Docker / containerd 目标进程发现。
14. 支持源码路由表与运行时路由表对比。
15. 支持异常请求日志与运行时组件关联。

---

## 30. 推荐实现顺序

推荐不要一开始就做清理，先实现扫描闭环：

```text
第一阶段：
PID 发现 → Attach → Agent 加载 → JVM 类枚举 → JSON 报告

第二阶段：
Tomcat Context 定位 → Filter/Servlet/Listener/Valve 枚举 → 评分

第三阶段：
Spring Context 定位 → Mapping/Interceptor/Bean 枚举 → 评分

第四阶段：
基线生成 → 基线对比 → 白名单 → HTML 报告

第五阶段：
dry-run 清理 → 按 ID 清理 → 快照 → 复扫 → 回滚
```

---

## 31. 最终效果示例

扫描命令：

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --format console
```

输出：

```text
[+] Target PID: 12345
[+] Java Version: 17.0.10
[+] Container: Tomcat 9.x
[+] Spring MVC: detected
[+] Scan finished

[CRITICAL] finding-filter-a3f92c1d
Type       : tomcat-filter
Name       : DebugFilter
Class      : com.example.Abc123
Pattern    : /*
CodeSource : null
Score      : 12
Reasons:
  - runtime only filter
  - url-pattern is /*
  - codeSource is null
  - bytecode contains ProcessBuilder

Recommended:
  1. Export evidence.
  2. Run clean dry-run.
  3. Confirm with business owner.
  4. Clean by finding ID.
  5. Restart service if necessary.
```

清理命令：

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar clean --id finding-filter-a3f92c1d --dry-run
```

确认清理：

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar clean --id finding-filter-a3f92c1d --confirm
```

复扫：

```bash
java -jar memshell-attach.jar 12345 ./memshell-agent.jar scan --format console
```

---

## 32. 结论

该工具本质上是一个防守型 Java 运行时安全检测工具。核心不是查文件，而是进入 JVM 内部检查运行时注册表、已加载类、容器组件和 Spring 映射关系。

设计关键点有三个：

1. **扫描必须全面**：JVM 类、Tomcat 组件、Spring Mapping、ClassLoader、字节码特征、基线对比都要覆盖。
2. **判断必须谨慎**：不能单靠关键字，需要多维度评分和白名单。
3. **清理必须保守**：默认只读，清理必须按 ID 执行，清理前保存证据，清理后复扫，无法安全处理时建议重启服务。

最终推荐落地形态：

```text
memshell-attach.jar + memshell-agent.jar
```

其中：

- `memshell-attach.jar` 负责连接目标 JVM。
- `memshell-agent.jar` 负责在目标 JVM 内部扫描、报告和清理。
- 默认只读扫描。
- 清理必须人工确认并指定 Finding ID。

---

## v0.7.1 - E2E evidence archive and Listener compatibility

Goals:

- Archive real `test-target` E2E artifacts in `docs/superpowers/specs/v0.7.1-clean-flow-evidence/`
- Verify clean disappearance for filter, servlet, listener, and valve findings
- Support Tomcat 9 listener storage names in scanner and cleaner paths
- Keep the v0.7 cleaner CLI contract unchanged
