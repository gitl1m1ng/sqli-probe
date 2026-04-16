# SQLi Probe

> **版本**: 1.0.0 | BurpSuite Pro SQL 注入辅助检测工具

BurpSuite SQL 注入批量检测插件，基于 Montoya API 开发。

## 功能特性

### 四种检测器

| 检测器 | 触发条件 | Payload 示例 | 判断逻辑 |
|--------|----------|--------------|----------|
| **字符型布尔盲注** | 所有参数 | `'`, `''`, `'+'`, `'\|\|'` | 单引号触发异常，闭合后恢复 = 注入存在 |
| **数字型注入** | 仅数字参数 | `*1`, `*0` | `*1` 不变 + `*0` 不同 = 参数参与 SQL 计算 |
| **Order By 注入** | 勾选时 | `,1`, `,999999` | 追加排序参数响应不同 = 注入存在 |
| **时间盲注** | 勾选时 | `SLEEP(5)` 变体 | 响应延迟 > 4秒 = 注入存在 |

### 核心能力

- **多数据源**：支持 Proxy History、SiteMap、右键发送
- **智能 Payload**：根据参数类型自动选择最合适的 Payload
- **过程透明**：实时展示每个请求的 Payload 和响应
- **人工研判**：提供原始数据和对比信息，辅助人工判断

## 快速开始

### 环境要求

- JDK 17+
- BurpSuite Pro 2024.12+ (需要 Montoya API 支持)
- Gradle 8.0+ (用于构建)

### 构建插件

```bash
./gradlew build
```

构建产物：`build/libs/sqli-probe.jar`

### 安装插件

1. 打开 BurpSuite → Extender → Extensions
2. 点击 "Add" → 选择 "JAR file"
3. 选择 `sqli-probe.jar`
4. 插件加载成功后，会在 BurpSuite 顶部标签栏显示 "SQLi Probe" 标签

## 使用方法

### 1. 添加扫描目标

**方式一：从 Proxy History 右键发送**
1. 在 Proxy → HTTP History 中选择请求
2. 右键 → "Send to SQLi Probe"

**方式二：从 SiteMap 右键发送**
1. 在 Target → Site Map 中选择请求
2. 右键 → "Send to SQLi Probe"

**方式三：从 Repeater / Proxy 请求框右键发送**
1. 在 Repeater 或 Proxy 请求编辑器中编辑请求
2. 右键 → "扩展" → "Send to SQLi Probe"（支持单条请求右键）

### 2. 配置检测选项

在插件主界面勾选要启用的检测器：

- [x] 字符型布尔盲注（建议勾选）
- [x] 数字型注入（建议勾选）
- [ ] Order By 注入（按需勾选）
- [ ] 时间盲注（按需勾选，注意：会增加扫描时间）

### 3. 执行扫描

1. 点击 "开始探测" 按钮
2. 观察任务列表中的进度
3. 查看探测详情表格

### 4. 查看结果

**任务列表**：显示所有探测任务，包含 URL、参数、方法、检测器、状态、结果

**探测详情**：选中任务后，下方表格显示每个 Payload 的测试结果

| 列 | 说明 |
|----|------|
| Payload | 注入 Payload |
| 状态码 | HTTP 响应状态码 |
| 响应长度 | 响应字节数 |
| 相似度 | 与 Baseline 的相似度百分比 |
| 响应时间 | 响应耗时（毫秒） |
| 结果概述 | 简短判断文字 |

**CompareDialog**：双击探测详情行，打开并排对比面板，直观对比 Baseline 与测试响应的差异

### 5. 导出报告

点击 "导出报告" 按钮，可将扫描结果导出为 HTML 格式。

## 检测逻辑详解

### 字符型布尔盲注

```
原始请求: GET /api/user?id=1

poc1:     GET /api/user?id=1'      → 响应异常（单引号未闭合）
poc2:     GET /api/user?id=1''     → 响应恢复正常（闭合成功）
poc3:     GET /api/user?id=1'+'    → 响应恢复正常（MySQL风格闭合）
poc4:     GET /api/user?id=1'||'   → 响应恢复正常（Oracle风格闭合）

结论:     poc1不同 且 poc2/3/4 任一相同 → 可疑（注入存在）
```

**相似度判定**：n-gram 相似度 < 0.95 或状态码不同

### 数字型注入

```
原始请求: GET /api/user?id=1

poc1:     GET /api/user?id=1*1    → 响应与 baseline 相同（SQL计算后仍为1）
poc2:     GET /api/user?id=1*0    → 响应与 baseline 不同（结果变为0）

结论:     poc1相同 且 poc2不同 → 可疑（参数参与SQL计算）
```

**触发条件**：仅对参数原始值为纯数字的参数生效

### 时间盲注

```
原始请求: GET /api/user?id=1

poc1:     GET /api/user?id=1' XOR SLEEP(5) XOR '    （字符型注入）
poc2:     GET /api/user?id=1 XOR SLEEP(5)            （数字型注入，仅数字参数）
poc3:     GET /api/user?id=1; SELECT SLEEP(5)         （通用）

结论:     任一响应时间 > baseline + 4秒 → 可疑
```

**注意**：数字参数会尝试全部三个 Payload；非数字参数只尝试 poc1 和 poc3

### Order By 注入

```
原始请求: GET /api/user?id=1

poc1:     GET /api/user?id=1,1         → 响应与 baseline 相同（追加排序）
poc2:     GET /api/user?id=1,999999    → 响应与 baseline 不同（超大分页）

结论:     poc1相同 且 poc2不同 → 可疑
```

## 检测盲点

本插件主要覆盖**布尔盲注**和**时间盲注**场景，以下注入类型**无法检测**：

| 类型 | 说明 |
|------|------|
| UNION 注入 | 需要构造 UNION SELECT 语句 |
| 报错型注入 | 需要触发数据库错误并回显 |
| 堆叠注入 | 需要多语句执行支持 |
| OOB 外带注入 | 需要 DNS/HTTP 外带检测 |
| 二次注入 | 数据先存储后触发 |

如需更全面的扫描能力，建议配合 BurpSuite Professional 的 Scanner 或 SQLMap 使用。

## 项目结构

```
sqli-probe/
├── src/
│   ├── main/java/com/example/burp/sqli/
│   │   ├── SqliProbeExtension.java    # 插件入口
│   │   ├── core/
│   │   │   ├── ProbeEngine.java       # 探测引擎
│   │   │   ├── ProbeTask.java          # 探测任务
│   │   │   └── ProbeResult.java        # 探测结果
│   │   ├── detector/
│   │   │   ├── Detector.java           # 检测器接口
│   │   │   ├── StringBlindDetector.java # 字符型布尔盲注
│   │   │   ├── NumericDetector.java     # 数字型注入
│   │   │   ├── OrderByDetector.java    # Order By 注入
│   │   │   └── TimeBlindDetector.java  # 时间盲注
│   │   ├── ui/
│   │   │   ├── ProbeTab.java           # 主界面
│   │   │   ├── SqliProbeContextMenu.java # 右键菜单
│   │   │   ├── CompareDialog.java       # 响应对比弹窗
│   │   │   └── ...
│   │   ├── export/
│   │   └── fingerprint/
│   └── test/java/
├── docs/                               # 开发文档
│   ├── 需求文档-SQL注入批量检测插件.md
│   └── 测试文档-SQLiProbe.md
├── build.gradle
└── settings.gradle
```

## 技术栈

- Java 17
- BurpSuite Montoya API 2025.12
- Gradle 8.0
- Swing (UI)

## Roadmap

> 欢迎提交 Issue 和 Pull Request。

### 后续计划

- [ ] **AI 辅助研判** — 引入大模型，自动分析响应内容，过滤误报，输出漏洞描述与修复建议
- [ ] **多语言数据库指纹** — MySQL / PostgreSQL / MSSQL / Oracle 分支 Payload 自适应
- [ ] **自定义参数** - 支持添加自定义参数
- [ ] **自定义payload** - 允许用户自定义注入Payload

## 版本历史

| 版本 | 说明 |
|------|------|
| v1.0.0 | 初始版本发布。包含四种检测器（字符型布尔盲注、数字型注入、Order By 注入、时间盲注）；支持 Proxy History / SiteMap / 消息编辑器右键发送；支持 JSON body 参数注入检测。 |

## 免责声明

本插件仅供安全测试和合法授权的渗透测试使用。使用本插件进行未授权的测试活动可能违反当地法律法规，使用者需自行承担风险。

---

**License**: MIT
