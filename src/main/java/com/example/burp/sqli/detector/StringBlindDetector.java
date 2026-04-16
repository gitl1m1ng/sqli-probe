package com.example.burp.sqli.detector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.example.burp.sqli.core.ProbeResult;
import com.example.burp.sqli.fingerprint.DbErrorFingerprint;

import java.util.List;

/**
 * 字符型布尔盲注检测器
 *
 * Payload:
 *   poc1: value'         → 引入未闭合单引号，期望响应异常 (false 基线)
 *   poc2: value''        → 双引号闭合，期望等同原始 (true 验证 A)
 *   poc3: value'+'       → MySQL 字符串拼接闭合，期望等同原始 (true 验证 B)
 *   poc4: value'||'      → Oracle/PG 风格拼接闭合，期望等同原始 (true 验证 C)
 *
 * 判定逻辑（v4.3 精化）：
 *   必要条件：resp(poc1) ≠ baseline（单引号使响应发生变化）
 *   满足以下任意一条即可判定可疑：
 *     条件 A：resp(poc2) ≈ baseline（双引号成功闭合）
 *     条件 B：resp(poc3) ≈ baseline 且 resp(poc3) ≠ resp(poc1)（'+'闭合成功）
 *     条件 C：resp(poc4) ≈ baseline 且 resp(poc4) ≠ resp(poc1)（'||'闭合成功）
 */
public class StringBlindDetector implements Detector {

    protected int timeoutMs = 10000;
    protected int delayMs = 0;

    @Override
    public void setTimeoutMs(int timeoutMs) { this.timeoutMs = Math.max(1000, timeoutMs); }
    @Override
    public void setDelayMs(int delayMs) { this.delayMs = Math.max(0, delayMs); }

    @Override
    public ProbeResult detect(MontoyaApi api, String url, String paramName,
                              String paramValue, HttpRequestResponse baseReq, String paramType) {
        ProbeResult result = new ProbeResult(url, paramName, paramValue, ProbeResult.DetectorType.STRING_BLIND);

        // 1) 直接使用引擎缓存的 baseline（不重复发送请求）
        //    baseReq 是引擎从队列中获取的原始请求/响应
        long baselineTime = 0;
        ProbeResult.ProbeEntry baselineEntry = new ProbeResult.ProbeEntry(
                "baseline", paramValue, baseReq, baselineTime, List.of());
        result.addEntry(baselineEntry);

        String baselineBody = getResponseBody(baselineEntry);

        // rawJson：仅 json 类型参数时才有值（从 InjectionPoint 传入，但 detect 接口无此参数）
        // 这里从 baseReq 的 body 获取完整原始 JSON 作为 fallback
        String rawJson = "json".equalsIgnoreCase(paramType) ? baseReq.request().bodyToString() : null;

        // 2) poc1: value'
        String poc1 = paramValue + "'";
        HttpRequest req1 = buildRequestWithParam(baseReq, paramName, poc1, paramType, rawJson);
        ProbeResult.ProbeEntry entry1 = sendAndRecord(api, "poc1: " + paramValue + "'", poc1, req1, timeoutMs, delayMs);
        result.addEntry(entry1);

        // 3) poc2: value''
        String poc2 = paramValue + "''";
        HttpRequest req2 = buildRequestWithParam(baseReq, paramName, poc2, paramType, rawJson);
        ProbeResult.ProbeEntry entry2 = sendAndRecord(api, "poc2: " + paramValue + "''", poc2, req2, timeoutMs, delayMs);
        result.addEntry(entry2);

        // 4) poc3: value'+'
        String poc3 = paramValue + "'+'";
        HttpRequest req3 = buildRequestWithParam(baseReq, paramName, poc3, paramType, rawJson);
        ProbeResult.ProbeEntry entry3 = sendAndRecord(api, "poc3: " + paramValue + "'+'", poc3, req3, timeoutMs, delayMs);
        result.addEntry(entry3);

        // 5) poc4: value'||'
        String poc4 = paramValue + "'||'";
        HttpRequest req4 = buildRequestWithParam(baseReq, paramName, poc4, paramType, rawJson);
        ProbeResult.ProbeEntry entry4 = sendAndRecord(api, "poc4: " + paramValue + "'||'", poc4, req4, timeoutMs, delayMs);
        result.addEntry(entry4);

        // 判定逻辑（保守策略，减少误报）
        String body1 = getResponseBody(entry1);
        String body2 = getResponseBody(entry2);
        String body3 = getResponseBody(entry3);
        String body4 = getResponseBody(entry4);

        // 长度差异率
        int baselineLen = baselineBody.length();
        int len1 = body1.length();
        int len2 = body2.length();
        int len3 = body3.length();
        int len4 = body4.length();

        double lengthDiffPct1 = baselineLen > 0 ? Math.abs(len1 - baselineLen) * 100.0 / baselineLen : 0;
        double lengthDiffPct2 = baselineLen > 0 ? Math.abs(len2 - baselineLen) * 100.0 / baselineLen : 0;
        double lengthDiffPct3 = baselineLen > 0 ? Math.abs(len3 - baselineLen) * 100.0 / baselineLen : 0;
        double lengthDiffPct4 = baselineLen > 0 ? Math.abs(len4 - baselineLen) * 100.0 / baselineLen : 0;

        // 相似度（n-gram）
        double diff1 = similarity(baselineBody, body1);
        double diff2 = similarity(baselineBody, body2);
        double diff3 = similarity(baselineBody, body3);
        double diff4 = similarity(baselineBody, body4);

        // ===== 布尔盲注判定逻辑（v5.1 最终版） =====
        //
        // 规则：当且仅当同时满足以下两个条件时，判定为存在注入：
        //   1. poc1（单引号）与 baseline 响应不同    → 单引号触发了 SQL 异常
        //   2. poc2/poc3/poc4 任一与 baseline 相同  → 闭合 payload 恢复了正常响应
        //
        // "响应不同"的判定：
        //   - 相似度 < 0.95 或 状态码不同 → 响应不同
        // "响应相同"的判定：
        //   - 相似度 > 0.95 且 状态码相同 → 响应相同

        // 获取 baseline 状态码
        int baselineStatusCode = baselineEntry.getStatusCode();

        // poc1 状态码
        int status1 = entry1.getStatusCode();
        boolean statusDiff1 = status1 != baselineStatusCode;

        // poc2~poc4 状态码
        int status2 = entry2.getStatusCode();
        int status3 = entry3.getStatusCode();
        int status4 = entry4.getStatusCode();

        // 响应是否与 baseline 不同（相似度<0.95 或 状态码不同）
        boolean poc1DiffBaseline = diff1 < 0.95 || statusDiff1;  // poc1 与 baseline 不同
        boolean poc2SameBaseline = diff2 > 0.95 && !statusDiff(status2, baselineStatusCode);  // poc2 与 baseline 相同
        boolean poc3SameBaseline = diff3 > 0.95 && !statusDiff(status3, baselineStatusCode);  // poc3 与 baseline 相同
        boolean poc4SameBaseline = diff4 > 0.95 && !statusDiff(status4, baselineStatusCode);  // poc4 与 baseline 相同

        boolean truePocRestored = poc2SameBaseline || poc3SameBaseline || poc4SameBaseline;

        if (poc1DiffBaseline && truePocRestored) {
            result.setStatus(ProbeResult.Status.SUSPICIOUS);
        } else {
            result.setStatus(ProbeResult.Status.SAFE);
        }

        return result;
    }

    /**
     * 构造替换参数后的请求
     * 支持 query / body（form-urlencoded）/ json / cookie
     */
    static HttpRequest buildRequestWithParam(HttpRequestResponse baseReq,
                                              String paramName, String newValue, String paramType) {
        return buildRequestWithParam(baseReq, paramName, newValue, paramType, null);
    }

    /**
     * 构造替换参数后的请求（JSON body 专用重载，携带原始 JSON 字符串）
     *
     * @param rawJson 仅当 paramType == "json" 时使用，原始完整 JSON body（来自 InjectionPoint.rawJson()）
     */
    static HttpRequest buildRequestWithParam(HttpRequestResponse baseReq,
                                              String paramName, String newValue, String paramType,
                                              String rawJson) {
        HttpRequest original = baseReq.request();
        String url = original.url();

        if ("query".equalsIgnoreCase(paramType) || paramType == null) {
            // 替换 URL 中的参数值
            String newUrl = replaceQueryParam(url, paramName, newValue);
            try {
                java.net.URL parsed = new java.net.URL(newUrl);
                String pathAndQuery = parsed.getPath();
                if (parsed.getQuery() != null) {
                    pathAndQuery += "?" + parsed.getQuery();
                }
                return original.withPath(pathAndQuery);
            } catch (java.net.MalformedURLException e) {
                return original;
            }
        }

        // json 参数：在原始 JSON body 中替换指定字段的值
        if ("json".equalsIgnoreCase(paramType)) {
            String sourceJson = (rawJson != null && !rawJson.isEmpty())
                    ? rawJson
                    : original.bodyToString();
            String newBody = replaceJsonParam(sourceJson, paramName, newValue);
            return original.withBody(ByteArray.byteArray(newBody));
        }

        // body 参数：替换 POST body 中的 form-urlencoded 参数
        if ("body".equalsIgnoreCase(paramType)) {
            String body = original.bodyToString();
            String newBody = replaceFormParam(body, paramName, newValue);
            return original.withBody(ByteArray.byteArray(newBody));
        }

        // cookie
        if ("cookie".equalsIgnoreCase(paramType)) {
            String cookie = original.headerValue("Cookie");
            if (cookie != null) {
                String newCookie = replaceCookieParam(cookie, paramName, newValue);
                return original.withUpdatedHeader("Cookie", newCookie);
            }
        }

        return original;
    }

    static ProbeResult.ProbeEntry sendAndRecord(MontoyaApi api, String label, String payload,
                                                 HttpRequest request) {
        return sendAndRecord(api, label, payload, request, 10000, 0);
    }

    /**
     * 发送请求并记录探测条目（支持超时和延迟）
     *
     * @param timeoutMs 单请求超时（毫秒）
     * @param delayMs   请求间延迟（毫秒）
     */
    static ProbeResult.ProbeEntry sendAndRecord(MontoyaApi api, String label, String payload,
                                                 HttpRequest request, int timeoutMs, int delayMs) {
        // 请求间延迟
        if (delayMs > 0) {
            try { Thread.sleep(delayMs); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }

        long start = System.currentTimeMillis();
        HttpRequestResponse resp;
        java.util.concurrent.FutureTask<HttpRequestResponse> futureTask = null;
        Thread sendThread = null;

        try {
            // 使用 FutureTask 实现超时控制（Montoya API 的 sendRequest 无内置超时参数）
            futureTask = new java.util.concurrent.FutureTask<>(() -> api.http().sendRequest(request));
            sendThread = new Thread(futureTask, "SQLiProbe-Send");
            sendThread.setDaemon(true);
            sendThread.start();

            // v6.0 修复：使用 wait/notify 模式实现更可靠的超时控制
            // 避免 futureTask.cancel() 在某些情况下无法中断阻塞的请求
            long remainingMs = timeoutMs;
            long waitStart = System.currentTimeMillis();
            boolean completed = false;

            while (remainingMs > 0 && !completed) {
                try {
                    synchronized (futureTask) {
                        completed = futureTask.isDone();
                        if (!completed) {
                            long waitTime = Math.min(remainingMs, 100); // 每 100ms 检查一次
                            long waitElapsed = System.currentTimeMillis() - waitStart;
                            waitTime = Math.min(waitTime, timeoutMs - waitElapsed);
                            if (waitTime > 0) {
                                futureTask.wait(waitTime);
                            }
                        }
                    }
                    if (!completed) {
                        long elapsed = System.currentTimeMillis() - waitStart;
                        remainingMs = timeoutMs - elapsed;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            // 检查是否完成
            boolean taskCompleted = futureTask.isDone();
            long elapsed = System.currentTimeMillis() - start;

            if (!taskCompleted) {
                // 超时：取消任务并返回 TIMEOUT entry
                futureTask.cancel(true); // 尝试中断线程
                // 强制等待一小段时间确保线程确实被中断
                try { Thread.sleep(50); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                api.logging().logToOutput("[SQLi Probe] Request timed out after " + elapsed + "ms: " + label + " (canceled)");
                return new ProbeResult.ProbeEntry(label + " (TIMEOUT)", payload, null,
                        elapsed, List.of("[TIMEOUT] Request exceeded " + timeoutMs + "ms"));
            }

            // 任务完成，尝试获取结果
            try {
                resp = futureTask.get(0, java.util.concurrent.TimeUnit.MILLISECONDS);
            } catch (java.util.concurrent.CancellationException e) {
                // 任务被取消（不应该发生，因为我们已经检查了 isDone()）
                api.logging().logToOutput("[SQLi Probe] Request canceled: " + label);
                return new ProbeResult.ProbeEntry(label + " (CANCELED)", payload, null,
                        elapsed, List.of("[CANCELED] Request was canceled"));
            } catch (java.util.concurrent.ExecutionException e) {
                // 请求执行失败
                api.logging().logToOutput("[SQLi Probe] Request failed (ExecutionException): " + label + " - " + e.getCause());
                return new ProbeResult.ProbeEntry(label + " (FAILED)", payload, null,
                        elapsed, List.of("[FAILED] " + (e.getCause() != null ? e.getCause().getMessage() : "Unknown error")));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                api.logging().logToOutput("[SQLi Probe] Request interrupted: " + label);
                return new ProbeResult.ProbeEntry(label + " (INTERRUPTED)", payload, null,
                        elapsed, List.of("[INTERRUPTED] Request was interrupted"));
            }

        } catch (Exception e) {
            api.logging().logToOutput("[SQLi Probe] Send failed: " + label + " - " + e.getMessage());
            return new ProbeResult.ProbeEntry(label + " (FAILED)", payload, null,
                    System.currentTimeMillis() - start, List.of("[FAILED] " + e.getMessage()));
        }
        long elapsed = System.currentTimeMillis() - start;

        // 检查 resp 和 response 是否为 null（sendThread 被中断后可能返回一个不完整的 response）
        if (resp == null) {
            api.logging().logToOutput("[SQLi Probe] Request completed but response is null: " + label);
            return new ProbeResult.ProbeEntry(label + " (NULL_RESPONSE)", payload, null,
                    elapsed, List.of("[NULL_RESPONSE] Response object is null after request completed"));
        }

        String fullResp = resp.response() != null ? resp.response().toString() : "";
        List<String> dbErrors = DbErrorFingerprint.detectWithDetails(fullResp);

        return new ProbeResult.ProbeEntry(label, payload, resp, elapsed, dbErrors);
    }

    static String getResponseBody(ProbeResult.ProbeEntry entry) {
        if (entry.getRequestResponse() == null || entry.getRequestResponse().response() == null) {
            return "";
        }
        return entry.getRequestResponse().response().bodyToString();
    }

    /**
     * 判断两个状态码是否不同
     * v5.1: 状态码不同也视为响应不同
     */
    static boolean statusDiff(int statusA, int statusB) {
        return statusA != statusB;
    }

    static double similarity(String a, String b) {
        if (a == null || b == null) return 0;
        if (a.equals(b)) return 1.0;
        int n = 4;
        java.util.Set<String> setA = ngrams(a, n);
        java.util.Set<String> setB = ngrams(b, n);
        if (setA.isEmpty() && setB.isEmpty()) return 1.0;
        if (setA.isEmpty() || setB.isEmpty()) return 0.0;
        int inter = 0;
        for (String g : setA) { if (setB.contains(g)) inter++; }
        return (double) inter / (setA.size() + setB.size() - inter);
    }

    private static java.util.Set<String> ngrams(String s, int n) {
        java.util.Set<String> set = new java.util.HashSet<>();
        if (s.length() < n) { set.add(s); return set; }
        for (int i = 0; i <= s.length() - n; i++) set.add(s.substring(i, i + n));
        return set;
    }

    // --- 参数替换工具方法 ---

    static String replaceQueryParam(String url, String name, String value) {
        String query = "";
        String base = url;
        int qIdx = url.indexOf('?');
        if (qIdx >= 0) {
            base = url.substring(0, qIdx);
            query = url.substring(qIdx + 1);
        } else {
            return url + "?" + name + "=" + java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
        }
        String[] pairs = query.split("&");
        StringBuilder sb = new StringBuilder("?");
        boolean found = false;
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(name)) {
                sb.append(name).append("=").append(java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8));
                found = true;
            } else if (kv.length == 2) {
                sb.append(kv[0]).append("=").append(kv[1]);
            } else if (kv.length == 1 && !kv[0].isEmpty()) {
                sb.append(kv[0]);
            }
            sb.append("&");
        }
        if (!found) {
            sb.append(name).append("=").append(java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8)).append("&");
        }
        String newQuery = sb.toString();
        if (newQuery.endsWith("&")) newQuery = newQuery.substring(0, newQuery.length() - 1);
        if (newQuery.endsWith("?")) newQuery = newQuery.substring(0, newQuery.length() - 1);
        return base + newQuery;
    }

    static String replaceFormParam(String body, String name, String value) {
        if (body == null) return "";
        String encodedValue = java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
        String[] pairs = body.split("&");
        StringBuilder sb = new StringBuilder();
        boolean found = false;
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(name)) {
                sb.append(name).append("=").append(encodedValue);
                found = true;
            } else if (kv.length == 2) {
                sb.append(kv[0]).append("=").append(kv[1]);
            } else if (kv.length == 1 && !kv[0].isEmpty()) {
                sb.append(kv[0]);
            }
            sb.append("&");
        }
        if (!found) {
            sb.append(name).append("=").append(encodedValue).append("&");
        }
        String result = sb.toString();
        if (result.endsWith("&")) result = result.substring(0, result.length() - 1);
        return result;
    }

    static String replaceCookieParam(String cookie, String name, String value) {
        String encodedValue = java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
        String[] parts = cookie.split(";\\s*");
        StringBuilder sb = new StringBuilder();
        boolean found = false;
        for (String part : parts) {
            String[] kv = part.split("=", 2);
            if (kv.length == 2 && kv[0].trim().equals(name)) {
                sb.append(name).append("=").append(encodedValue);
                found = true;
            } else {
                sb.append(part);
            }
            sb.append("; ");
        }
        if (!found) {
            sb.append(name).append("=").append(encodedValue).append("; ");
        }
        return sb.toString().trim();
    }

    /**
     * 替换 JSON body 中指定字段的值（支持嵌套路径，如 "user.name"）
     *
     * 实现思路：使用正则定位目标字符串/数字字段并替换其值。
     * 对于字符串型字段，将新值 JSON 转义后替换引号内内容。
     * 对于数字/布尔/null 型字段，直接替换字面量。
     * 支持嵌套路径（"a.b.c"），递归处理子对象。
     *
     * @param json      原始 JSON 字符串
     * @param fieldPath 字段路径（支持 "." 分隔的嵌套路径）
     * @param newValue  新字段值（未转义的原始字符串，方法内会处理转义）
     * @return 替换后的 JSON 字符串
     */
    static String replaceJsonParam(String json, String fieldPath, String newValue) {
        if (json == null || json.trim().isEmpty()) return json;
        if (fieldPath == null || fieldPath.isEmpty()) return json;

        // 将新值进行 JSON 字符串转义（注入 Payload 可能含有单引号、反斜杠等）
        String escapedValue = jsonEscape(newValue);

        // 使用 JsonFieldReplacer 精确替换指定字段的值
        try {
            return JsonFieldReplacer.replace(json, fieldPath, escapedValue);
        } catch (Exception e) {
            // 替换失败，静默返回原始 JSON（不破坏请求）
            return json;
        }
    }

    /**
     * 将字符串进行 JSON 转义（用于生成 JSON 字符串字面量内容）
     */
    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * JSON 字段值替换工具（支持嵌套路径）
     * 采用字符扫描方式，精确定位目标字段并替换值，不破坏 JSON 结构
     */
    private static class JsonFieldReplacer {

        /**
         * 将 json 中 fieldPath 对应字段的值替换为 newEscapedValue（已转义的字符串内容）
         * 返回替换后的 JSON
         */
        static String replace(String json, String fieldPath, String newEscapedValue) {
            String[] parts = fieldPath.split("\\.", 2);
            String key = parts[0];
            String rest = parts.length > 1 ? parts[1] : null;

            // 找到 key 在当前 JSON 对象中对应的值的起始位置和范围
            int[] valueRange = findFieldValueRange(json, key);
            if (valueRange == null) return json; // 字段不存在

            int valueStart = valueRange[0];
            int valueEnd   = valueRange[1]; // exclusive

            if (rest != null) {
                // 还有嵌套层，递归处理子 JSON
                String subJson = json.substring(valueStart, valueEnd);
                String replacedSub = replace(subJson, rest, newEscapedValue);
                return json.substring(0, valueStart) + replacedSub + json.substring(valueEnd);
            }

            // 最终字段：直接替换值
            // 判断值类型：字符串还是字面量
            char firstChar = json.charAt(valueStart);
            String newValueToken;
            if (firstChar == '"') {
                // 字符串类型：用转义后的值替换引号内内容
                newValueToken = "\"" + newEscapedValue + "\"";
            } else {
                // 数字/布尔/null：将新值作为字符串注入（也用引号包裹，因为 Payload 含特殊字符）
                newValueToken = "\"" + newEscapedValue + "\"";
            }

            return json.substring(0, valueStart) + newValueToken + json.substring(valueEnd);
        }

        /**
         * 在 JSON 字符串中找到指定 key 对应值的 [start, end) 位置（相对于 json 字符串）
         * 只处理顶层对象的直接字段
         * 返回 null 如果 key 不存在
         */
        static int[] findFieldValueRange(String json, String key) {
            if (json == null || json.trim().isEmpty()) return null;
            String trimmed = json.trim();
            if (!trimmed.startsWith("{")) return null;

            int pos = 0;
            int len = json.length();

            // 跳到 '{'
            while (pos < len && json.charAt(pos) != '{') pos++;
            if (pos >= len) return null;
            pos++; // skip '{'

            while (pos < len) {
                // skip whitespace
                while (pos < len && Character.isWhitespace(json.charAt(pos))) pos++;
                if (pos >= len) break;

                char c = json.charAt(pos);
                if (c == '}') break;
                if (c == ',') { pos++; continue; }

                // parse key string
                if (c != '"') break; // malformed
                int[] keyRange = readStringRange(json, pos);
                if (keyRange == null) break;
                String parsedKey = json.substring(keyRange[0] + 1, keyRange[1] - 1); // strip quotes
                // unescape basic escapes for comparison
                parsedKey = unescapeSimple(parsedKey);
                pos = keyRange[1]; // move past closing quote

                // skip whitespace + ':'
                while (pos < len && Character.isWhitespace(json.charAt(pos))) pos++;
                if (pos >= len || json.charAt(pos) != ':') break;
                pos++; // skip ':'
                while (pos < len && Character.isWhitespace(json.charAt(pos))) pos++;

                // now pos is at value start
                int valueStart = pos;

                // skip value
                int valueEnd = skipValue(json, pos);
                pos = valueEnd;

                if (parsedKey.equals(key)) {
                    // trim trailing whitespace within value
                    return new int[]{valueStart, valueEnd};
                }
            }
            return null;
        }

        /** 读取 JSON 字符串的 [start, end) 范围（包括两端引号） */
        static int[] readStringRange(String json, int start) {
            if (json.charAt(start) != '"') return null;
            int pos = start + 1;
            while (pos < json.length()) {
                char c = json.charAt(pos);
                if (c == '\\') {
                    pos += 2; // skip escape
                } else if (c == '"') {
                    return new int[]{start, pos + 1};
                } else {
                    pos++;
                }
            }
            return null;
        }

        /** 跳过一个 JSON 值（字符串/数字/布尔/null/对象/数组），返回值结束后的位置 */
        static int skipValue(String json, int pos) {
            int len = json.length();
            if (pos >= len) return pos;
            char c = json.charAt(pos);
            if (c == '"') {
                // string
                int[] r = readStringRange(json, pos);
                return r != null ? r[1] : pos + 1;
            } else if (c == '{') {
                return skipBracketed(json, pos, '{', '}');
            } else if (c == '[') {
                return skipBracketed(json, pos, '[', ']');
            } else {
                // number / boolean / null — read until delimiter
                while (pos < len) {
                    char ch = json.charAt(pos);
                    if (ch == ',' || ch == '}' || ch == ']' || Character.isWhitespace(ch)) break;
                    pos++;
                }
                return pos;
            }
        }

        static int skipBracketed(String json, int pos, char open, char close) {
            int depth = 0;
            int len = json.length();
            while (pos < len) {
                char c = json.charAt(pos);
                if (c == '"') {
                    int[] r = readStringRange(json, pos);
                    pos = r != null ? r[1] : pos + 1;
                    continue;
                }
                if (c == open)  depth++;
                if (c == close) { depth--; if (depth == 0) return pos + 1; }
                pos++;
            }
            return pos;
        }

        static String unescapeSimple(String s) {
            return s.replace("\\\"", "\"")
                    .replace("\\\\", "\\")
                    .replace("\\/", "/")
                    .replace("\\n", "\n")
                    .replace("\\t", "\t")
                    .replace("\\r", "\r");
        }
    }
}

