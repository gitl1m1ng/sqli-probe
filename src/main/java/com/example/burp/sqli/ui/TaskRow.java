package com.example.burp.sqli.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import com.example.burp.sqli.core.ProbeResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 统一任务行模型（v4.0）
 * 
 * 每个任务行对应一个 URL，从入队到完成始终在同一行。
 * 状态机：QUEUED → EXTRACTING → TESTING → SUSPICIOUS/SAFE/ERROR/SKIPPED
 * 
 * 一个 URL 可以产生多个 ProbeResult（每个注入点一个），
 * 行的总体状态取所有 result 中"最严重"的状态。
 */
public class TaskRow {

    public enum TaskStatus {
        QUEUED("⏳ 等待"),
        EXTRACTING("🔍 提取注入点"),
        TESTING("🔵 测试中"),
        SUSPICIOUS("⚠ 可疑"),
        SAFE("✓ 安全"),
        SKIPPED("⚪ 跳过"),
        ERROR("✗ 错误");

        private final String label;
        TaskStatus(String label) { this.label = label; }
        public String getLabel() { return label; }
    }

    // === 队列信息 ===
    private final HttpRequest request;
    private final HttpResponse response;
    private final String source;

    // === 状态 ===
    private volatile TaskStatus status = TaskStatus.QUEUED;
    private volatile String currentTestInfo = "";       // "当前测试"列内容
    private volatile int injectionPointCount = -1;       // -1 = 尚未提取

    // === 探测结果（每个注入点一个） ===
    private final List<ProbeResult> results = new CopyOnWriteArrayList<>();

    // === 探测进度 ===
    private final AtomicInteger pendingProbeCount = new AtomicInteger(0);

    // === 时间戳 ===
    private final long createdAt = System.currentTimeMillis();

    public TaskRow(HttpRequest request, HttpResponse response, String source) {
        this.request = request;
        this.response = response;
        this.source = source;
    }

    // --- Getters ---

    public HttpRequest getRequest() { return request; }
    public HttpResponse getResponse() { return response; }
    public String getSource() { return source; }
    public TaskStatus getStatus() { return status; }
    public String getCurrentTestInfo() { return currentTestInfo; }
    public int getInjectionPointCount() { return injectionPointCount; }
    public List<ProbeResult> getResults() { return Collections.unmodifiableList(results); }
    public long getCreatedAt() { return createdAt; }

    public boolean hasResponse() { return response != null; }

    // --- URL 工具方法 ---

    public String getUrl() {
        try {
            return request.url();
        } catch (MalformedRequestException e) {
            return "(malformed)";
        }
    }

    public String getMethod() {
        return request.method();
    }

    public int getStatusCode() {
        return hasResponse() ? response.statusCode() : 0;
    }

    /**
     * 短 URL（去掉 scheme 和 host，截断显示）
     */
    public String getShortUrl() {
        try {
            String url = request.url();
            int schemeEnd = url.indexOf("://");
            if (schemeEnd >= 0) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart >= 0) {
                    url = url.substring(pathStart);
                } else {
                    url = "/";
                }
            }
            return url.length() > 80 ? url.substring(0, 77) + "..." : url;
        } catch (Exception e) {
            return "(malformed)";
        }
    }

    // --- 结果相关 ---

    /**
     * 获取总体状态（取所有 result 中最严重的）
     */
    public TaskStatus getOverallStatus() {
        if (status == TaskStatus.SKIPPED || status == TaskStatus.ERROR) {
            return status;
        }
        if (status == TaskStatus.QUEUED || status == TaskStatus.EXTRACTING || status == TaskStatus.TESTING) {
            return status;
        }
        // SUSPICIOUS / SAFE — 取最严重的
        for (ProbeResult r : results) {
            if (r.getStatus() == ProbeResult.Status.SUSPICIOUS) {
                return TaskStatus.SUSPICIOUS;
            }
        }
        return TaskStatus.SAFE;
    }

    /**
     * 获取主要检测器类型（第一个有结果的）
     */
    public ProbeResult.DetectorType getPrimaryDetectorType() {
        for (ProbeResult r : results) {
            if (r.getStatus() != ProbeResult.Status.PENDING) {
                return r.getDetectorType();
            }
        }
        return null;
    }

    /**
     * 是否有可疑结果
     */
    public boolean hasSuspicious() {
        for (ProbeResult r : results) {
            if (r.getStatus() == ProbeResult.Status.SUSPICIOUS) return true;
        }
        return false;
    }

    /**
     * 是否已完成（不再变化）
     */
    public boolean isFinished() {
        return status == TaskStatus.SUSPICIOUS || status == TaskStatus.SAFE
                || status == TaskStatus.SKIPPED || status == TaskStatus.ERROR;
    }

    /**
     * 最大长度差异百分比
     */
    public double getMaxLengthDiffPercent() {
        double max = 0;
        for (ProbeResult r : results) {
            max = Math.max(max, r.getMaxLengthDiffPercent());
        }
        return max;
    }

    /**
     * 总耗时
     */
    public long getTotalTimeMs() {
        long total = 0;
        for (ProbeResult r : results) {
            total += r.getTotalTimeMs();
        }
        return total;
    }

    /**
     * 是否有 DB 错误
     */
    public boolean hasDbErrors() {
        for (ProbeResult r : results) {
            if (r.hasDbErrors()) return true;
        }
        return false;
    }

    /**
     * 结果摘要文字（用于表格"结果摘要"列）
     */
    public String getResultSummary() {
        if (status == TaskStatus.SKIPPED) return "无注入点";
        if (status == TaskStatus.ERROR) return "请求失败";
        if (!isFinished()) return "";
        int total = results.size();
        int suspicious = 0;
        for (ProbeResult r : results) {
            if (r.getStatus() == ProbeResult.Status.SUSPICIOUS) suspicious++;
        }
        if (suspicious > 0) return "⚠ " + suspicious + "/" + total + " 可疑";
        return "✓ " + total + " 安全";
    }

    // --- Setters（供引擎调用）---

    public void setStatus(TaskStatus status) { this.status = status; }
    public void setCurrentTestInfo(String info) { this.currentTestInfo = info; }
    public void setInjectionPointCount(int count) { this.injectionPointCount = count; }

    public void addResult(ProbeResult result) {
        this.results.add(result);
    }

    /**
     * 清除所有探测结果（用于重新探测）
     */
    public void clearResults() {
        this.results.clear();
        this.pendingProbeCount.set(0);
        this.injectionPointCount = -1;
        this.currentTestInfo = "";
        this.status = TaskStatus.QUEUED;
    }

    // --- 探测进度 ---

    public int getPendingProbeCount() { return pendingProbeCount.get(); }
    public void setPendingProbeCount(int count) { pendingProbeCount.set(count); }
    public int decrementPendingProbeCount() { return pendingProbeCount.decrementAndGet(); }
}
