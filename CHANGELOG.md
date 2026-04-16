# CHANGELOG

## [Unreleased]

### Planned

- AI 辅助研判（自动分析响应 + 误报过滤）
- 自定义参数白名单
- 自定义请求头注入检测
- 被动扫描模式

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
