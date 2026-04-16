package com.example.burp.sqli.export;

import com.example.burp.sqli.core.ProbeResult;
import com.example.burp.sqli.util.ResponseComparator;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * HTML 报告导出器
 * 将所有探测结果导出为可读的 HTML 报告，含请求/响应对比。
 */
public final class HtmlExporter {

    private HtmlExporter() {}

    public static void export(List<ProbeResult> results, String filePath) throws IOException {
        StringBuilder html = new StringBuilder();

        html.append("<!DOCTYPE html>\n");
        html.append("<html><head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<title>SQLi Probe Report</title>\n");
        html.append(STYLE);
        html.append("</head><body>\n");

        // 报告头
        html.append("<div class=\"header\">\n");
        html.append("<h1>SQLi Probe - 探测报告</h1>\n");
        html.append("<p>生成时间: ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("</p>\n");
        html.append("<p>总结果数: ").append(results.size());
        long suspicious = results.stream().filter(r -> r.getStatus() == ProbeResult.Status.SUSPICIOUS).count();
        html.append(" | 可疑: <span class=\"suspicious\">").append(suspicious).append("</span>");
        html.append(" | 安全: <span class=\"safe\">").append(results.size() - suspicious).append("</span></p>\n");
        html.append("</div>\n");

        // 结果列表
        html.append("<div class=\"results\">\n");
        for (int i = 0; i < results.size(); i++) {
            ProbeResult r = results.get(i);
            appendResult(html, i + 1, r);
        }
        html.append("</div>\n");

        html.append("</body></html>");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, StandardCharsets.UTF_8))) {
            writer.write(html.toString());
        }
    }

    private static void appendResult(StringBuilder html, int index, ProbeResult r) {
        boolean suspicious = r.getStatus() == ProbeResult.Status.SUSPICIOUS;
        html.append("<div class=\"result-card ").append(suspicious ? "card-suspicious" : "card-safe").append("\">\n");
        html.append("<div class=\"result-header\">\n");
        html.append("<span class=\"index\">#").append(index).append("</span>\n");
        html.append("<span class=\"url\">").append(escapeHtml(r.getUrl())).append("</span>\n");
        html.append("<span class=\"param\">参数: <b>").append(escapeHtml(r.getParamName())).append("</b> = ").append(escapeHtml(r.getParamValue())).append("</span>\n");
        html.append("<span class=\"type\">").append(r.getDetectorType().getLabel()).append("</span>\n");
        html.append("<span class=\"status ").append(suspicious ? "suspicious" : "safe").append("\">")
                .append(suspicious ? "\u26A0 可疑" : "\u2713 安全").append("</span>\n");
        html.append("<span class=\"diff\">长度差: ").append(String.format("%.1f%%", r.getMaxLengthDiffPercent())).append("</span>\n");
        html.append("<span class=\"time\">耗时: ").append(formatTime(r.getTotalTimeMs())).append("</span>\n");
        if (r.hasDbErrors()) {
            html.append("<span class=\"db-error\">\uD83D\uDD34 DB错误</span>\n");
        }
        html.append("</div>\n");

        // 请求/响应对比
        html.append("<div class=\"entries\">\n");
        ProbeResult.ProbeEntry baseline = r.getBaseline();
        int baselineLength = baseline != null ? baseline.getResponseLength() : 0;

        for (ProbeResult.ProbeEntry entry : r.getEntries()) {
            html.append("<div class=\"entry\">\n");
            html.append("<div class=\"entry-info\">\n");
            html.append("<b>").append(escapeHtml(entry.getLabel())).append("</b>\n");
            html.append("<br>状态: ").append(entry.getStatusCode());
            html.append(" | 长度: ").append(entry.getResponseLength());
            html.append(" | 耗时: ").append(entry.getResponseTimeMs()).append("ms");

            double diffPct = entry.getLengthDiffPercent(baselineLength);
            if (diffPct > 10) {
                html.append(" | <span class=\"diff-highlight\">长度差异: ").append(String.format("+%.1f%%", diffPct)).append("</span>");
            }

            if (entry.hasDbErrors()) {
                html.append("<br><span class=\"db-error-detail\">DB错误: ");
                html.append(escapeHtml(String.join(", ", entry.getDbErrors()))).append("</span>\n");
            }

            html.append("</div>\n");

            // 响应体（截断显示）
            String responseBody = "";
            if (entry.getRequestResponse() != null && entry.getRequestResponse().response() != null) {
                responseBody = entry.getRequestResponse().response().bodyToString();
            }

            String baselineBody = "";
            if (baseline != null && baseline.getRequestResponse() != null && baseline.getRequestResponse().response() != null) {
                baselineBody = baseline.getRequestResponse().response().bodyToString();
            }

            String displayBody;
            if (entry == baseline) {
                displayBody = escapeHtml(responseBody);
            } else {
                displayBody = ResponseComparator.highlightDifferencesHtml(baselineBody, responseBody);
            }

            if (displayBody.length() > 5000) {
                displayBody = displayBody.substring(0, 5000) + "\n... (truncated)";
            }

            html.append("<pre class=\"response-body\">").append(displayBody).append("</pre>\n");
            html.append("</div>\n"); // entry
        }
        html.append("</div>\n"); // entries
        html.append("</div>\n"); // result-card
    }

    private static String formatTime(long ms) {
        if (ms < 1000) return ms + "ms";
        return String.format("%.1fs", ms / 1000.0);
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static final String STYLE = """
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; color: #333; }
                .header { background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                .header h1 { margin: 0 0 8px 0; color: #1a1a2e; }
                .suspicious { color: #dc3545; font-weight: bold; }
                .safe { color: #28a745; font-weight: bold; }
                .result-card { background: #fff; border-radius: 8px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
                .card-suspicious { border-left: 4px solid #dc3545; }
                .card-safe { border-left: 4px solid #28a745; }
                .result-header { padding: 12px 16px; background: #fafafa; border-bottom: 1px solid #eee; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
                .result-header .index { font-weight: bold; color: #666; min-width: 40px; }
                .result-header .url { font-family: monospace; font-size: 13px; color: #555; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                .result-header .param { font-size: 13px; }
                .result-header .type { background: #e9ecef; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
                .result-header .diff { font-size: 12px; color: #666; }
                .result-header .time { font-size: 12px; color: #666; }
                .result-header .db-error { color: #dc3545; font-size: 12px; font-weight: bold; }
                .entries { padding: 8px; }
                .entry { border: 1px solid #eee; border-radius: 4px; margin-bottom: 8px; overflow: hidden; }
                .entry-info { padding: 8px 12px; background: #fafafa; border-bottom: 1px solid #eee; font-size: 13px; }
                .diff-highlight { color: #e67e22; font-weight: bold; }
                .db-error-detail { color: #dc3545; }
                .response-body { background: #1e1e1e; color: #d4d4d4; padding: 12px; margin: 8px; border-radius: 4px; font-size: 11px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
                mark { background: #fff3cd; padding: 0 2px; border-radius: 2px; }
            </style>
            """;
}
