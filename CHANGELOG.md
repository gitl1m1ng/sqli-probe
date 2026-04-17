# CHANGELOG

## [Unreleased]

### Planned

- AI 辅助研判（自动分析响应 + 误报过滤）
- 自定义参数白名单
- 自定义请求头注入检测
- 被动扫描模式

## [1.0.3] - 2026-04-17

### Changed

- **时间盲注数字型 Payload 优化**：数字参数的时间盲注 Payload 从 `0 XOR SLEEP(5)` 改为 `1*SLEEP(5)`，避免 MySQL 常量折叠优化导致 SLEEP 函数被跳过

### Fixed

- **超时条目点击后请求区为空**：`sendAndRecord` 超时/失败时现在保留请求对象（包装为 `HttpRequestResponse(request, null)`），点击超时条目可在请求区看到带 Payload 的完整请求，方便直接发送到 Repeater
- **超时条目误显示"检测到DB错误"**：`EntryTableModel.getResultSummary()` 新增对 TIMEOUT / CANCELED / FAILED / INTERRUPTED / ERROR label 的专项判断，显示"请求超时，无响应数据"等准确描述，不再走 DB 错误检测逻辑

## [1.0.2] - 2026-04-17

### Fixed

- **超时条目点击后请求区为空**：`sendAndRecord` 超时/失败时现在保留请求对象（包装为 `HttpRequestResponse(request, null)`），点击超时条目可在请求区看到带 Payload 的完整请求，方便直接发送到 Repeater
- **超时条目误显示"检测到DB错误"**：`EntryTableModel.getResultSummary()` 新增对 TIMEOUT / CANCELED / FAILED / INTERRUPTED / ERROR label 的专项判断，显示"请求超时，无响应数据"等准确描述，不再走 DB 错误检测逻辑

## [1.0.1] - 2026-04-17

### Fixed

- **去重 Key 加入 HTTP Method**：`GET /api` 与 `POST /api` 不再被误判为重复任务
- **去重支持 JSON body 字段名**：`request.parameters()` 不返回 JSON 字段，改用字符扫描提取顶层 key；`POST /api {"name":"a"}` 与 `POST /api {"name":"b"}` 可正确识别为重复

## [1.0.0] - 2026-04-16

### Added

- **字符型布尔盲注检测器**（StringBlindDetector）
- **数字型注入检测器**（NumericDetector）
- **时间盲注检测器**（TimeBlindDetector）
- **Order By 注入检测器**（OrderByDetector）
- **JSON body 参数注入支持**
- **多数据源右键发送**（列表选中 + 消息编辑器上下文）
- **响应对比面板**（CompareDialog）
- **HTML 报告导出**

### Limitations

本插件**不检测**：UNION 注入、报错型注入、堆叠注入、OOB 外带注入、二次注入。
