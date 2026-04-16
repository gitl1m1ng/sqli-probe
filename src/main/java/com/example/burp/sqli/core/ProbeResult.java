package com.example.burp.sqli.core;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 单个探测结果数据模型
 * 记录一个参数点的所有探测请求/响应，供 UI 展示和人工判断。
 */
public class ProbeResult {

    public enum Status {
        SUSPICIOUS("可疑"),
        SAFE("安全"),
        PENDING("待检");

        private final String label;
        Status(String label) { this.label = label; }
        public String getLabel() { return label; }
    }

    public enum DetectorType {
        STRING_BLIND("字符型盲注"),
        NUMERIC("数字型"),
        ORDER_BY("Order型"),
        TIME_BLIND("时间盲注");

        private final String label;
        DetectorType(String label) { this.label = label; }
        public String getLabel() { return label; }
    }

    /** 探测序列中的一条记录 */
    public static class ProbeEntry {
        private final String label;       // "原始" / "poc1: value'" / "poc2: value''" 等
        private final String payload;     // 实际注入的 payload
        private final HttpRequestResponse requestResponse;
        private final long responseTimeMs;
        private final int responseLength;
        private final int statusCode;
        private final List<String> dbErrors; // 匹配到的数据库错误特征

        public ProbeEntry(String label, String payload, HttpRequestResponse requestResponse,
                          long responseTimeMs, List<String> dbErrors) {
            this.label = label;
            this.payload = payload;
            this.requestResponse = requestResponse;
            this.responseTimeMs = responseTimeMs;
            // v6.0 修复：同时检查 requestResponse 和 response 是否为 null
            this.responseLength = requestResponse != null && requestResponse.response() != null
                    ? requestResponse.response().bodyToString().length() : 0;
            this.statusCode = requestResponse != null && requestResponse.response() != null
                    ? requestResponse.response().statusCode() : 0;
            this.dbErrors = dbErrors != null ? dbErrors : Collections.emptyList();
        }

        public String getLabel() { return label; }
        public String getPayload() { return payload; }
        public HttpRequestResponse getRequestResponse() { return requestResponse; }
        public long getResponseTimeMs() { return responseTimeMs; }
        public int getResponseLength() { return responseLength; }
        public int getStatusCode() { return statusCode; }
        public List<String> getDbErrors() { return dbErrors; }
        public boolean hasDbErrors() { return !dbErrors.isEmpty(); }

        /** 与 baseline 的响应长度差异百分比 */
        public double getLengthDiffPercent(int baselineLength) {
            if (baselineLength == 0) return 0;
            return Math.abs(responseLength - baselineLength) * 100.0 / baselineLength;
        }
    }

    private final String url;
    private final String paramName;
    private final String paramValue;
    private final DetectorType detectorType;
    private final List<ProbeEntry> entries = new ArrayList<>();
    private volatile Status status = Status.PENDING;

    // 手动标记（用户可覆盖自动判定）
    private volatile Boolean userMarked = null; // null=未标记, true=可疑, false=安全

    public ProbeResult(String url, String paramName, String paramValue, DetectorType detectorType) {
        this.url = url;
        this.paramName = paramName;
        this.paramValue = paramValue;
        this.detectorType = detectorType;
    }

    public void addEntry(ProbeEntry entry) { entries.add(entry); }
    public List<ProbeEntry> getEntries() { return Collections.unmodifiableList(entries); }

    public String getUrl() { return url; }
    public String getParamName() { return paramName; }
    public String getParamValue() { return paramValue; }
    public DetectorType getDetectorType() { return detectorType; }

    public Status getStatus() {
        if (userMarked != null) return userMarked ? Status.SUSPICIOUS : Status.SAFE;
        return status;
    }

    public void setStatus(Status status) { this.status = status; }

    public void setUserMarked(Boolean marked) { this.userMarked = marked; }
    public Boolean getUserMarked() { return userMarked; }

    /** 获取 baseline（第一个 entry，即原始请求） */
    public ProbeEntry getBaseline() {
        return entries.isEmpty() ? null : entries.get(0);
    }

    /** 获取最大长度差异百分比（相对于 baseline） */
    public double getMaxLengthDiffPercent() {
        ProbeEntry baseline = getBaseline();
        if (baseline == null) return 0;
        return entries.stream()
                .mapToDouble(e -> e.getLengthDiffPercent(baseline.getResponseLength()))
                .max()
                .orElse(0);
    }

    /** 获取总耗时 */
    public long getTotalTimeMs() {
        return entries.stream().mapToLong(ProbeEntry::getResponseTimeMs).sum();
    }

    /** 是否包含数据库错误特征 */
    public boolean hasDbErrors() {
        return entries.stream().anyMatch(ProbeEntry::hasDbErrors);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s | %s=%s | %s",
                status.getLabel(), shortUrl(url), paramName, paramValue, detectorType.getLabel());
    }

    private static String shortUrl(String url) {
        if (url == null) return "";
        return url.length() > 60 ? url.substring(0, 57) + "..." : url;
    }
}
