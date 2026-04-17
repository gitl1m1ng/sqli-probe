package com.example.burp.sqli.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import com.example.burp.sqli.detector.*;
import com.example.burp.sqli.ui.TaskRow;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.SwingUtilities;

/**
 * 探测引擎（v4.1）
 *
 * 核心变更（相比 v4.0）：
 *   - 支持重新探测：reprobeTask() / reprobeSelected() 可对已完成/停止的任务重新执行
 *   - 修复状态管理：100% 完成后正确切换到 IDLE，停止后可以重新开始
 *   - 新增 state 变更回调通知 UI 更新按钮状态
 *   - shutdown 不再直接设 IDLE，由 checkAllComplete 统一判断
 *
 * 架构：
 *   - 队列存储 TaskRow（统一封装 HttpRequest + HttpResponse + 状态）
 *   - startFromQueue() → 将所有 QUEUED 状态任务提交到线程池的 prepare 阶段
 *   - reprobeTask(row) → 重置指定 TaskRow 的状态和结果，重新执行探测
 *   - prepareAndSubmit(taskRow) → 提取注入点 → 为每个注入点提交探测任务
 *   - runProbe(taskRow, ...) → 逐个检测器执行，实时更新 taskRow 状态
 */
public class ProbeEngine {

    public enum EngineState { IDLE, RUNNING, PAUSED, STOPPED }

    /**
     * 任务更新监听器（替代原 QueueChangeListener）
     * 提供细粒度更新：行添加、行变更、结果接收、状态变更
     */
    public interface TaskUpdateListener {
        /** 全量刷新（初始化/批量添加后） */
        void onTasksReset();
        /** 某一行数据变更（状态、当前测试信息等） */
        void onTaskUpdated(TaskRow row, int allRowIndex);
        /** 接收到一个探测结果（用于详情面板实时更新） */
        void onResultReceived(TaskRow row, ProbeResult result);
        /** 队列被清空 */
        void onTasksCleared();
        /** 引擎状态变更（用于 UI 更新按钮 enabled 状态） */
        default void onEngineStateChanged(EngineState newState) {}
    }

    private TaskUpdateListener taskUpdateListener;

    private final MontoyaApi api;

    private ExecutorService executor;
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final AtomicBoolean stopped = new AtomicBoolean(false);
    private volatile EngineState state = EngineState.IDLE;

    // 进度追踪
    private final AtomicInteger totalTasks = new AtomicInteger(0);
    private final AtomicInteger completedTasks = new AtomicInteger(0);
    private final AtomicInteger suspiciousCount = new AtomicInteger(0);
    private final AtomicInteger safeCount = new AtomicInteger(0);
    private final AtomicInteger prepareTasks = new AtomicInteger(0);
    private final AtomicInteger prepareCompleted = new AtomicInteger(0);
    private final AtomicBoolean allPrepared = new AtomicBoolean(false);

    // 配置
    private int concurrency = 5;
    private int timeoutMs = 10000;
    private int delayMs = 0;
    private boolean enableStringBlind = true;
    private boolean enableNumeric = true;
    private boolean enableOrderBy = true;
    private boolean enableTimeBlind = false;
    private boolean enableCookieInjection = false;
    private boolean onlyInScope = true;
    private Set<String> excludedExtensions = Set.of(
            "jpg", "png", "gif", "css", "js", "ico", "woff", "woff2", "svg", "ttf", "eot");

    // 统一任务列表
    private final List<TaskRow> taskRows = Collections.synchronizedList(new ArrayList<>());

    public ProbeEngine(MontoyaApi api) {
        this.api = api;
    }

    // --- 配置 Setter ---

    public void setConcurrency(int v) { this.concurrency = Math.max(1, Math.min(v, 50)); }
    public void setTimeoutMs(int v) { this.timeoutMs = Math.max(1000, Math.min(v, 120000)); }
    public void setDelayMs(int v) { this.delayMs = Math.max(0, Math.min(v, 30000)); }
    public void setEnableStringBlind(boolean v) { this.enableStringBlind = v; }
    public void setEnableNumeric(boolean v) { this.enableNumeric = v; }
    public void setEnableOrderBy(boolean v) { this.enableOrderBy = v; }
    public void setEnableTimeBlind(boolean v) { this.enableTimeBlind = v; }
    public void setEnableCookieInjection(boolean v) { this.enableCookieInjection = v; }
    public void setOnlyInScope(boolean v) { this.onlyInScope = v; }
    public void setExcludedExtensions(Set<String> ext) { this.excludedExtensions = ext; }
    public int getTimeoutMs() { return timeoutMs; }
    public int getDelayMs() { return delayMs; }

    // --- 任务操作 ---

    /**
     * 添加 HttpRequestResponse 到任务列表（来自右键菜单 "Send to SQLi Probe"）
     * v6.0: 移除自动去重，所有请求都会添加，由用户手动点击「🔍 去重」按钮去重
     */
    public void addRequestResponses(List<HttpRequestResponse> requestResponses, String source) {
        addRequestResponses(requestResponses, source, true);
    }

    /**
     * 内部通用方法
     * @param notifyReset 是否通知 UI 全量刷新
     * v6.0: 移除自动去重，所有请求都会添加到任务列表
     */
    private void addRequestResponses(List<HttpRequestResponse> requestResponses, String source, boolean notifyReset) {
        if (requestResponses == null) return;
        int added = 0;
        int skipped = 0;
        synchronized (taskRows) {
            for (HttpRequestResponse rr : requestResponses) {
                try {
                    TaskRow row = new TaskRow(rr.request(), rr.response(), source);
                    taskRows.add(row);
                    added++;
                } catch (MalformedRequestException e) {
                    skipped++;
                }
            }
        }
        if (skipped > 0) {
            api.logging().logToOutput("[SQLi Probe] Skipped " + skipped + " malformed request(s).");
        }
        api.logging().logToOutput("[SQLi Probe] Added " + added + " request(s) from " + source + " (total: " + taskRows.size() + "). "
                + "Tip: Click '🔍 去重' to remove duplicate tasks.");

        if (notifyReset) {
            SwingUtilities.invokeLater(() -> {
                if (taskUpdateListener != null) taskUpdateListener.onTasksReset();
            });
        }
    }

    /**
     * 手动去重：移除重复的任务
     * v6.0: 新增手动去重功能
     * v1.0.1: 修复两处局限：
     *   1. 加入 HTTP Method 前缀，区分 GET /api 与 POST /api
     *   2. 对 JSON body 单独解析字段名（request.parameters() 不返回 JSON 字段）
     *
     * 去重规则：Method + URL 路径 + 参数名集合（不管顺序和参数值）= 重复项
     * 示例：
     *   GET  /api?id=1 和 GET  /api?id=2  → 重复（Method+路径+参数名 完全一致）
     *   POST /api?id=1 和 GET  /api?id=1  → 不重复（Method 不同）
     *   POST /api body:{"name":"a"}  和  POST /api body:{"name":"b"} → 重复（JSON 字段名相同）
     *   POST /api body:{"name":"a"}  和  POST /api body:{"age":1}   → 不重复（字段名不同）
     */
    public int deduplicate() {
        int removed = 0;
        synchronized (taskRows) {
            Set<String> seenKeys = new java.util.HashSet<>();
            List<TaskRow> toRemove = new java.util.ArrayList<>();

            for (TaskRow row : taskRows) {
                try {
                    HttpRequest request = row.getRequest();

                    // 1. HTTP Method（区分 GET/POST/PUT/DELETE 等）
                    String method = request.method() != null ? request.method().toUpperCase() : "GET";

                    // 2. URL 路径（截掉 ? 之后的部分）
                    String baseUrl = getBaseUrl(request.url());

                    // 3. 收集参数名
                    List<String> paramNames = new java.util.ArrayList<>();

                    // 3a. Query 参数名（来自 URL）
                    for (HttpParameter p : request.parameters()) {
                        if (p.type() == HttpParameterType.URL) {
                            paramNames.add(p.name());
                        }
                    }

                    // 3b. Body 参数名
                    String contentType = request.headerValue("Content-Type");
                    if (contentType != null && contentType.contains("application/json")) {
                        // JSON body：request.parameters() 不含 JSON 字段，需自行解析
                        String body = request.bodyToString();
                        if (body != null && !body.isBlank()) {
                            extractJsonFieldNames(body, paramNames);
                        }
                    } else {
                        // form-urlencoded / multipart：直接用 Montoya API
                        for (HttpParameter p : request.parameters()) {
                            if (p.type() == HttpParameterType.BODY) {
                                paramNames.add(p.name());
                            }
                        }
                    }

                    // 4. 排序后拼接，忽略参数顺序
                    java.util.Collections.sort(paramNames);
                    String paramKey = String.join(",", paramNames);

                    // 5. 完整 key = Method + "|" + 路径 + "|" + 参数名列表
                    String key = method + "|" + baseUrl + "|" + paramKey;

                    if (seenKeys.contains(key)) {
                        toRemove.add(row);
                    } else {
                        seenKeys.add(key);
                    }
                } catch (Exception e) {
                    // 解析失败时保留该行，不误删
                }
            }

            for (TaskRow row : toRemove) {
                taskRows.remove(row);
                removed++;
            }
        }
        
        api.logging().logToOutput("[SQLi Probe] Deduplicated: removed " + removed + " duplicate(s), remaining: " + taskRows.size() + ".");
        
        SwingUtilities.invokeLater(() -> {
            if (taskUpdateListener != null) taskUpdateListener.onTasksReset();
        });
        
        return removed;
    }
    
    /**
     * 提取 URL 的基础路径（不含 Query 参数）
     */
    private String getBaseUrl(String url) {
        int qmIndex = url.indexOf('?');
        return qmIndex > 0 ? url.substring(0, qmIndex) : url;
    }

    /**
     * 从 JSON 字符串中提取顶层字段名，用于去重 Key 构建。
     * 仅提取最外层 Object 的 key，不递归嵌套（避免过度细粒度导致漏报）。
     * 例如：{"user":{"name":"a"},"age":1} → 提取 ["user","age"]
     *
     * 实现：简单字符扫描，无需引入 JSON 库，兼容 fat jar 打包限制。
     */
    private void extractJsonFieldNames(String json, List<String> out) {
        // 找到最外层 { }
        int start = json.indexOf('{');
        if (start < 0) return;

        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        StringBuilder key = new StringBuilder();
        boolean collectingKey = false;

        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);

            if (escaped) {
                if (collectingKey) key.append(c);
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                if (collectingKey) key.append(c);
                continue;
            }

            if (c == '"') {
                if (!inString) {
                    // 只在 depth==1 时（最外层 object 的直接子 key）才收集
                    if (depth == 1) {
                        collectingKey = true;
                        key.setLength(0);
                    }
                    inString = true;
                } else {
                    inString = false;
                    if (collectingKey) {
                        // 需要确认紧接着是 ':'，才算 key
                        // 先暂存，后面遇到 ':' 才加入 out
                        String candidate = key.toString();
                        // 跳过空白找 ':'
                        int j = i + 1;
                        while (j < json.length() && Character.isWhitespace(json.charAt(j))) j++;
                        if (j < json.length() && json.charAt(j) == ':') {
                            out.add(candidate);
                        }
                        collectingKey = false;
                    }
                }
                continue;
            }

            if (inString) {
                if (collectingKey) key.append(c);
                continue;
            }

            if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
                if (depth == 0) break; // 最外层结束
            }
        }
    }

    /**
     * 从 Proxy History 批量加载到任务列表（异步）
     */
    public void loadFromProxyHistory() {
        new Thread(() -> {
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                api.logging().logToOutput("[SQLi Probe] Proxy History returned " + history.size() + " items.");

                List<HttpRequestResponse> valid = new ArrayList<>();
                int skipped = 0;
                for (ProxyHttpRequestResponse proxyRR : history) {
                    try {
                        String url = proxyRR.request().url();
                        if (onlyInScope && !api.scope().isInScope(url)) { skipped++; continue; }
                        if (ProbeTask.shouldExcludeExtension(url, excludedExtensions)) { skipped++; continue; }
                        valid.add(HttpRequestResponse.httpRequestResponse(proxyRR.request(), proxyRR.response()));
                    } catch (MalformedRequestException e) { skipped++; }
                }
                addRequestResponses(valid, "Proxy History");
                api.logging().logToOutput("[SQLi Probe] Loaded from Proxy History (" + skipped + " filtered/skipped).");
            } catch (Exception e) {
                api.logging().logToError("[SQLi Probe] Error loading from Proxy History: " + e.getMessage());
                e.printStackTrace();
            }
        }, "SQLiProbe-LoadProxy").start();
    }

    /**
     * 清空所有任务
     */
    public void clearTasks() {
        stop();
        taskRows.clear();
        api.logging().logToOutput("[SQLi Probe] Tasks cleared.");
        SwingUtilities.invokeLater(() -> {
            if (taskUpdateListener != null) taskUpdateListener.onTasksCleared();
        });
    }

    /**
     * 从列表中移除指定索引的任务
     */
    public boolean removeTask(int index) {
        synchronized (taskRows) {
            if (index >= 0 && index < taskRows.size()) {
                TaskRow removed = taskRows.remove(index);
                api.logging().logToOutput("[SQLi Probe] Removed task: " + removed.getUrl());
                SwingUtilities.invokeLater(() -> {
                    if (taskUpdateListener != null) taskUpdateListener.onTasksReset();
                });
                return true;
            }
        }
        return false;
    }

    public int getTaskCount() { return taskRows.size(); }

    /**
     * 获取任务列表快照（只读副本）
     */
    public List<TaskRow> getTaskRowsSnapshot() {
        synchronized (taskRows) {
            return new ArrayList<>(taskRows);
        }
    }

    // ========== 控制 ==========

    /**
     * 从任务列表启动探测
     * - 如果有待测任务（QUEUED），开始探测这些任务
     * - 如果引擎处于 STOPPED 状态且有待测任务，重新开始
     * - 如果引擎处于 IDLE 状态且有待测任务，开始探测
     * - 如果没有待测任务，提示用户可以右键使用"重新探测"
     */
    public void startFromQueue() {
        List<TaskRow> pending;
        synchronized (taskRows) {
            pending = taskRows.stream()
                    .filter(tr -> tr.getStatus() == TaskRow.TaskStatus.QUEUED)
                    .toList();
        }

        if (pending.isEmpty()) {
            // 没有待测任务，检查是否有已完成的任务可以重新探测
            synchronized (taskRows) {
                long completedCount = taskRows.stream()
                        .filter(tr -> tr.isFinished())
                        .count();
                if (completedCount > 0) {
                    api.logging().logToOutput("[SQLi Probe] No pending tasks. " + completedCount + " task(s) completed. "
                            + "Right-click on a task and select '重新探测（使用当前配置）' to re-scan with new settings.");
                } else {
                    api.logging().logToOutput("[SQLi Probe] No pending tasks. Add requests first or use 'Reprobe' on completed tasks.");
                }
            }
            return;
        }

        if (state == EngineState.RUNNING || state == EngineState.PAUSED) {
            if (state == EngineState.PAUSED) {
                // 当前暂停中，恢复运行
                resume();
                return;
            }
            api.logging().logToOutput("[SQLi Probe] Already running. Stop or pause first.");
            return;
        }

        // 标记为 EXTRACTING
        synchronized (taskRows) {
            for (TaskRow tr : pending) {
                tr.setStatus(TaskRow.TaskStatus.EXTRACTING);
            }
        }
        SwingUtilities.invokeLater(() -> {
            if (taskUpdateListener != null) taskUpdateListener.onTasksReset();
        });

        api.logging().logToOutput("[SQLi Probe] Starting with " + pending.size() + " pending tasks.");
        startWithTasks(pending);
    }

    /**
     * 重新探测指定的单个任务（重置状态和结果，重新执行）
     *
     * @param taskRow 要重新探测的任务行
     */
    public void reprobeTask(TaskRow taskRow) {
        if (taskRow == null) return;

        // 如果引擎正在运行且不是 STOPPED 状态，不允许重新探测
        if (state == EngineState.RUNNING || state == EngineState.PAUSED) {
            api.logging().logToOutput("[SQLi Probe] Cannot reprobe while engine is running/paused. Stop first.");
            return;
        }

        // 重置任务状态
        resetTaskForRowReprobe(taskRow);

        api.logging().logToOutput("[SQLi Probe] Reprobing: " + taskRow.getUrl());
        startWithTasks(List.of(taskRow));
    }

    /**
     * 重新探测多个任务（重置状态和结果，重新执行）
     */
    public void reprobeTasks(List<TaskRow> rows) {
        if (rows == null || rows.isEmpty()) return;

        if (state == EngineState.RUNNING || state == EngineState.PAUSED) {
            api.logging().logToOutput("[SQLi Probe] Cannot reprobe while engine is running/paused. Stop first.");
            return;
        }

        for (TaskRow row : rows) {
            resetTaskForRowReprobe(row);
        }

        api.logging().logToOutput("[SQLi Probe] Reprobing " + rows.size() + " task(s).");
        startWithTasks(rows);
    }

    /**
     * 重置单个 TaskRow 的状态和结果，准备重新探测
     */
    private void resetTaskForRowReprobe(TaskRow taskRow) {
        taskRow.clearResults();
        taskRow.setStatus(TaskRow.TaskStatus.QUEUED);
        taskRow.setCurrentTestInfo("");
        taskRow.setInjectionPointCount(-1);
        taskRow.setPendingProbeCount(0);
    }

    private void startWithTasks(List<TaskRow> tasks) {
        if (tasks == null || tasks.isEmpty()) return;

        // 如果是重新探测（从 STOPPED/IDLE 状态开始），不需要重置计数器
        // 如果是新的一轮探测，重置
        boolean isFreshStart = (state != EngineState.STOPPED)
                || (completedTasks.get() == 0 && totalTasks.get() == 0);

        if (isFreshStart) {
            totalTasks.set(0);
            completedTasks.set(0);
            suspiciousCount.set(0);
            safeCount.set(0);
        }

        // 先关闭旧的 executor（如果有）
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
            try { executor.awaitTermination(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        }

        stopped.set(false);
        paused.set(false);
        prepareTasks.set(tasks.size());
        prepareCompleted.set(0);
        allPrepared.set(false);

        executor = Executors.newFixedThreadPool(concurrency);
        setEngineState(EngineState.RUNNING);

        api.logging().logToOutput("[SQLi Probe] Engine started, concurrency=" + concurrency);

        for (TaskRow task : tasks) {
            task.setStatus(TaskRow.TaskStatus.EXTRACTING);
            executor.submit(() -> prepareAndSubmit(task));
        }

        SwingUtilities.invokeLater(() -> {
            if (taskUpdateListener != null) taskUpdateListener.onTasksReset();
        });
    }

    /**
     * 准备阶段：提取注入点，为每个注入点提交探测任务
     */
    private void prepareAndSubmit(TaskRow taskRow) {
        if (stopped.get()) { onPrepareComplete(); return; }

        String url = taskRow.getUrl();

        // 检查扩展名排除
        if (ProbeTask.shouldExcludeExtension(url, excludedExtensions)) {
            taskRow.setStatus(TaskRow.TaskStatus.SKIPPED);
            notifyTaskUpdated(taskRow);
            onPrepareComplete();
            return;
        }

        // 获取 baseline response
        HttpRequestResponse baseReq;
        if (taskRow.hasResponse()) {
            baseReq = HttpRequestResponse.httpRequestResponse(taskRow.getRequest(), taskRow.getResponse());
        } else {
            api.logging().logToOutput("[SQLi Probe] No cached response for " + url + ", sending...");
            try {
                baseReq = api.http().sendRequest(taskRow.getRequest());
            } catch (Exception e) {
                api.logging().logToError("[SQLi Probe] Failed to send request to " + url + ": " + e.getMessage());
                taskRow.setStatus(TaskRow.TaskStatus.ERROR);
                notifyTaskUpdated(taskRow);
                onPrepareComplete();
                return;
            }
        }

        if (baseReq == null || baseReq.response() == null) {
            api.logging().logToError("[SQLi Probe] No response for " + url);
            taskRow.setStatus(TaskRow.TaskStatus.ERROR);
            notifyTaskUpdated(taskRow);
            onPrepareComplete();
            return;
        }

        api.logging().logToOutput("[SQLi Probe] Processing: " + url + " [method=" + taskRow.getMethod()
                + ", status=" + baseReq.response().statusCode()
                + ", body=" + baseReq.response().body().length() + " bytes"
                + (taskRow.hasResponse() ? " (cached)" : " (re-sent)") + "]");

        // 提取注入点（根据 Cookie 开关决定是否提取 Cookie 参数）
        List<ProbeTask.InjectionPoint> points;
        try {
            points = ProbeTask.extractInjectionPoints(baseReq, enableCookieInjection);
        } catch (Exception e) {
            api.logging().logToError("[SQLi Probe] Error extracting injection points from " + url + ": " + e.getMessage());
            e.printStackTrace();
            taskRow.setStatus(TaskRow.TaskStatus.ERROR);
            notifyTaskUpdated(taskRow);
            onPrepareComplete();
            return;
        }

        if (points.isEmpty()) {
            try {
                String reqUrl = baseReq.request().url();
                boolean hasQuery = reqUrl.indexOf('?') >= 0;
                api.logging().logToOutput("[SQLi Probe] No injection points in " + url
                        + " [hasQuery=" + hasQuery + ", method=" + baseReq.request().method()
                        + ", cookieInjection=" + enableCookieInjection + "]");
            } catch (MalformedRequestException ex) { /* skip */ }

            taskRow.setStatus(TaskRow.TaskStatus.SKIPPED);
            taskRow.setInjectionPointCount(0);
            notifyTaskUpdated(taskRow);
            onPrepareComplete();
            return;
        }

        api.logging().logToOutput("[SQLi Probe] Found " + points.size() + " injection point(s) in " + url + ": " + points);

        // 设置探测计数，标记为 TESTING
        taskRow.setInjectionPointCount(points.size());
        taskRow.setPendingProbeCount(points.size());
        taskRow.setStatus(TaskRow.TaskStatus.TESTING);
        notifyTaskUpdated(taskRow);

        // 为每个注入点提交探测任务
        for (ProbeTask.InjectionPoint point : points) {
            if (stopped.get()) break;
            totalTasks.incrementAndGet();
            executor.submit(() -> runProbe(taskRow, url, point, baseReq));
        }

        onPrepareComplete();
    }

    /**
     * 运行单个注入点的探测链（v6.0）
     * 所有勾选的检测器都会执行，最后综合判定
     *
     * 修复（v5.8.1）：移除每个检测器执行完后的提前return，
     * 确保所有勾选的检测器都执行完毕后再综合判定。
     * v6.0: 添加详细调试日志，定位 UI 不显示时间盲注的问题
     */
    private void runProbe(TaskRow taskRow, String url, ProbeTask.InjectionPoint point, HttpRequestResponse baseReq) {
        // 暂停检查
        while (paused.get() && !stopped.get()) {
            try { Thread.sleep(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
        }
        if (stopped.get()) {
            completedTasks.incrementAndGet();
            checkTaskComplete(taskRow);
            return;
        }

        String paramName = point.paramName();
        java.util.List<ProbeResult> allResults = new java.util.ArrayList<>();

        // v6.0: 调试日志 - 显示当前检测器开关状态
        api.logging().logToOutput(String.format(
                "[SQLi Probe] Detector config: STRING=%s, NUMERIC=%s, ORDER=%s, TIME=%s | param=%s",
                enableStringBlind, enableNumeric, enableOrderBy, enableTimeBlind, paramName));

        try {
            // 1) 字符型盲注（勾选时执行）
            if (enableStringBlind) {
                taskRow.setCurrentTestInfo(paramName + ": 字符型盲注");
                notifyTaskUpdated(taskRow);

                StringBlindDetector d = new StringBlindDetector();
                d.setTimeoutMs(timeoutMs);
                d.setDelayMs(delayMs);
                ProbeResult r = d.detect(api, url, paramName, point.paramValue(), baseReq, point.paramType());

                if (!r.getEntries().isEmpty()) {
                    taskRow.addResult(r);
                    notifyResultReceived(taskRow, r);
                    api.logging().logToOutput(String.format(
                            "[SQLi Probe] Added STRING result: status=%s, entries=%d",
                            r.getStatus(), r.getEntries().size()));
                }
                allResults.add(r);
            }

            // 检查暂停/停止
            if (stopped.get()) {
                api.logging().logToOutput("[SQLi Probe] STOPPED after STRING_BLIND: " + paramName);
                completedTasks.incrementAndGet();
                checkTaskComplete(taskRow);
                return;
            }
            while (paused.get() && !stopped.get()) {
                try { Thread.sleep(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
            }

            // 2) 数字型注入（勾选时执行，仅对参数值为数字的参数）
            if (enableNumeric && NumericDetector.isNumericParam(point.paramValue())) {
                taskRow.setCurrentTestInfo(paramName + ": 数字型");
                notifyTaskUpdated(taskRow);

                NumericDetector d = new NumericDetector();
                d.setTimeoutMs(timeoutMs);
                d.setDelayMs(delayMs);
                ProbeResult r = d.detect(api, url, paramName, point.paramValue(), baseReq, point.paramType());

                if (!r.getEntries().isEmpty()) {
                    taskRow.addResult(r);
                    notifyResultReceived(taskRow, r);
                    api.logging().logToOutput(String.format(
                            "[SQLi Probe] Added NUMERIC result: status=%s, entries=%d",
                            r.getStatus(), r.getEntries().size()));
                }
                allResults.add(r);
            } else if (enableNumeric && !NumericDetector.isNumericParam(point.paramValue())) {
                api.logging().logToOutput(String.format(
                        "[SQLi Probe] Skipping NumericDetector for non-numeric param: %s=%s",
                        paramName, point.paramValue()));
            }

            if (stopped.get()) {
                api.logging().logToOutput("[SQLi Probe] STOPPED after NUMERIC: " + paramName);
                completedTasks.incrementAndGet();
                checkTaskComplete(taskRow);
                return;
            }
            while (paused.get() && !stopped.get()) {
                try { Thread.sleep(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
            }

            // 3) Order By 注入（勾选时执行，对所有参数）
            if (enableOrderBy) {
                taskRow.setCurrentTestInfo(paramName + ": Order By");
                notifyTaskUpdated(taskRow);

                OrderByDetector d = new OrderByDetector();
                d.setTimeoutMs(timeoutMs);
                d.setDelayMs(delayMs);
                ProbeResult r = d.detect(api, url, paramName, point.paramValue(), baseReq, point.paramType());

                if (!r.getEntries().isEmpty()) {
                    taskRow.addResult(r);
                    notifyResultReceived(taskRow, r);
                    api.logging().logToOutput(String.format(
                            "[SQLi Probe] Added ORDER_BY result: status=%s, entries=%d",
                            r.getStatus(), r.getEntries().size()));
                }
                allResults.add(r);
            }

            if (stopped.get()) {
                api.logging().logToOutput("[SQLi Probe] STOPPED after ORDER_BY: " + paramName);
                completedTasks.incrementAndGet();
                checkTaskComplete(taskRow);
                return;
            }
            while (paused.get() && !stopped.get()) {
                try { Thread.sleep(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
            }

            // 4) 时间盲注（勾选时执行）
            if (enableTimeBlind) {
                taskRow.setCurrentTestInfo(paramName + ": 时间盲注");
                notifyTaskUpdated(taskRow);

                TimeBlindDetector d = new TimeBlindDetector();
                d.setTimeoutMs(timeoutMs);
                d.setDelayMs(delayMs);
                ProbeResult r = d.detect(api, url, paramName, point.paramValue(), baseReq, point.paramType());

                if (!r.getEntries().isEmpty()) {
                    taskRow.addResult(r);
                    notifyResultReceived(taskRow, r);
                    api.logging().logToOutput(String.format(
                            "[SQLi Probe] Added TIME_BLIND result: status=%s, entries=%d",
                            r.getStatus(), r.getEntries().size()));
                } else {
                    api.logging().logToOutput(String.format(
                            "[SQLi Probe] WARNING: TIME_BLIND returned EMPTY entries for %s=%s",
                            paramName, point.paramValue()));
                }
                allResults.add(r);
            } else {
                api.logging().logToOutput(String.format(
                        "[SQLi Probe] TimeBlind SKIPPED (not enabled) for param: %s", paramName));
            }

            // ===== 综合判定 =====
            // 所有检测器都执行完毕后，再综合判定
            // 任一检测器发现可疑即为可疑
            boolean hasSuspicious = false;
            String firstSuspiciousType = "";
            for (ProbeResult r : allResults) {
                // 调试日志
                String dbg = String.format("[SQLi Probe] Detector=%s, Status=%s, Entries=%d",
                        r.getDetectorType(), r.getStatus(), r.getEntries().size());
                api.logging().logToOutput(dbg);
                if (r.getStatus() == ProbeResult.Status.SUSPICIOUS && !hasSuspicious) {
                    hasSuspicious = true;
                    firstSuspiciousType = switch (r.getDetectorType()) {
                        case STRING_BLIND -> "StringBlind";
                        case NUMERIC -> "Numeric";
                        case ORDER_BY -> "OrderBy";
                        case TIME_BLIND -> "TimeBlind";
                    };
                }
            }

            completedTasks.incrementAndGet();
            if (hasSuspicious) {
                suspiciousCount.incrementAndGet();
                api.logging().logToOutput("[SQLi Probe] ⚠ SUSPICIOUS: " + url + " [" + paramName + "] (" + firstSuspiciousType + ")");
            } else {
                safeCount.incrementAndGet();
            }

        } catch (Exception e) {
            completedTasks.incrementAndGet();
            api.logging().logToError("[SQLi Probe] Error probing " + url + " " + paramName + ": " + e.getMessage());
            e.printStackTrace();
        }

        checkTaskComplete(taskRow);
    }

    /**
     * 检查某个 TaskRow 的所有注入点是否都已探测完成
     * 如果全部完成，更新 TaskRow 的最终状态
     */
    private void checkTaskComplete(TaskRow taskRow) {
        if (taskRow.decrementPendingProbeCount() == 0) {
            // 所有注入点探测完毕
            if (taskRow.hasSuspicious()) {
                taskRow.setStatus(TaskRow.TaskStatus.SUSPICIOUS);
            } else if (!taskRow.getResults().isEmpty()) {
                taskRow.setStatus(TaskRow.TaskStatus.SAFE);
            } else {
                taskRow.setStatus(TaskRow.TaskStatus.SAFE);
            }
            taskRow.setCurrentTestInfo("");
            notifyTaskUpdated(taskRow);
            checkAllComplete();
        }
    }

    /**
     * 检查是否所有任务都已完成，如果是则自动切换到 IDLE
     */
    private void checkAllComplete() {
        if (allPrepared.get() && completedTasks.get() >= totalTasks.get() && totalTasks.get() > 0) {
            // 所有探测任务完成
            if (state == EngineState.RUNNING) {
                api.logging().logToOutput("[SQLi Probe] All tasks completed. "
                        + suspiciousCount.get() + " suspicious, " + safeCount.get() + " safe.");
                shutdownExecutor();
                setEngineState(EngineState.IDLE);
            }
        }
    }

    private void onPrepareComplete() {
        int completed = prepareCompleted.incrementAndGet();
        if (completed >= prepareTasks.get()) {
            allPrepared.set(true);
            if (totalTasks.get() == 0) {
                api.logging().logToOutput("[SQLi Probe] No injectable parameters found in any request.");
                shutdownExecutor();
                setEngineState(EngineState.IDLE);
            } else {
                // 可能所有探测任务已经在 executor 中完成了
                checkAllComplete();
            }
        }
    }

    // --- 控制 ---

    public void pause() {
        if (state != EngineState.RUNNING) return;
        paused.set(true);
        setEngineState(EngineState.PAUSED);
        api.logging().logToOutput("[SQLi Probe] Paused.");
    }

    public void resume() {
        if (state != EngineState.PAUSED) return;
        paused.set(false);
        setEngineState(EngineState.RUNNING);
        api.logging().logToOutput("[SQLi Probe] Resumed.");
    }

    public void stop() {
        stopped.set(true);
        paused.set(false);
        shutdownExecutor();

        // 将所有 TESTING/EXTRACTING 状态的任务标记为已停止（保留结果）
        synchronized (taskRows) {
            for (TaskRow row : taskRows) {
                TaskRow.TaskStatus s = row.getStatus();
                if (s == TaskRow.TaskStatus.TESTING || s == TaskRow.TaskStatus.EXTRACTING) {
                    // 保留已有的结果，标记最终状态
                    if (row.hasSuspicious()) {
                        row.setStatus(TaskRow.TaskStatus.SUSPICIOUS);
                    } else if (!row.getResults().isEmpty()) {
                        row.setStatus(TaskRow.TaskStatus.SAFE);
                    } else {
                        row.setStatus(TaskRow.TaskStatus.SKIPPED);
                    }
                    row.setCurrentTestInfo("");
                }
            }
        }

        setEngineState(EngineState.STOPPED);
        api.logging().logToOutput("[SQLi Probe] Stopped.");

        // 通知 UI 刷新
        SwingUtilities.invokeLater(() -> {
            if (taskUpdateListener != null) taskUpdateListener.onTasksReset();
        });
    }

    private void shutdownExecutor() {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
            try { executor.awaitTermination(3, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        }
    }

    /**
     * 设置引擎状态并通知 UI
     */
    private void setEngineState(EngineState newState) {
        this.state = newState;
        SwingUtilities.invokeLater(() -> {
            if (taskUpdateListener != null) {
                taskUpdateListener.onEngineStateChanged(newState);
            }
        });
    }

    // --- 进度查询 ---

    public EngineState getState() { return state; }
    public int getTotalTasks() { return totalTasks.get(); }
    public int getCompletedTasks() { return completedTasks.get(); }
    public int getSuspiciousCount() { return suspiciousCount.get(); }
    public int getSafeCount() { return safeCount.get(); }
    public int getPendingTasks() { return Math.max(0, totalTasks.get() - completedTasks.get()); }
    public double getProgressPercent() {
        int total = totalTasks.get();
        return total == 0 ? 0 : (completedTasks.get() * 100.0 / total);
    }

    // --- 监听器 ---

    public void setTaskUpdateListener(TaskUpdateListener listener) {
        this.taskUpdateListener = listener;
    }

    private void notifyTaskUpdated(TaskRow row) {
        if (taskUpdateListener != null) {
            int idx = taskRows.indexOf(row);
            SwingUtilities.invokeLater(() -> {
                taskUpdateListener.onTaskUpdated(row, idx);
            });
        }
    }

    private void notifyResultReceived(TaskRow row, ProbeResult result) {
        if (taskUpdateListener != null) {
            SwingUtilities.invokeLater(() -> {
                taskUpdateListener.onResultReceived(row, result);
            });
        }
    }

    /**
     * 插件卸载时调用
     */
    public void cleanup() {
        stop();
    }
}
