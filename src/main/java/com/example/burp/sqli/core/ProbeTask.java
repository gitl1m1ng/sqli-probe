package com.example.burp.sqli.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.example.burp.sqli.detector.*;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 单个探测任务
 * 对一个 URL 的一个参数执行完整的检测链：
 *   字符型盲注 → 数字型（条件） → Order型（条件） → 时间盲注（条件+开关）
 */
public class ProbeTask {

    /**
     * 从一个请求中提取的所有注入点
     * paramType 可能的值：query / body（form-urlencoded）/ json（application/json）/ cookie
     * rawJson 仅当 paramType == "json" 时有值，保存完整原始 JSON 字符串，用于替换时重建 body
     */
    public record InjectionPoint(String paramName, String paramValue, String paramType, String rawJson) {
        /** 兼容旧调用：rawJson 为 null */
        public InjectionPoint(String paramName, String paramValue, String paramType) {
            this(paramName, paramValue, paramType, null);
        }
    }

    /**
     * 从请求中提取注入点（Query + POST Body + Cookie）
     * 默认提取 Cookie 参数（保持向后兼容）
     */
    public static java.util.List<InjectionPoint> extractInjectionPoints(HttpRequestResponse req) {
        return extractInjectionPoints(req, true);
    }

    /**
     * 从请求中提取注入点（Query + POST Body + Cookie）
     *
     * @param req                   HTTP 请求响应对
     * @param enableCookieInjection 是否提取 Cookie 参数（v4.0 新增开关，默认关闭）
     */
    public static java.util.List<InjectionPoint> extractInjectionPoints(HttpRequestResponse req, boolean enableCookieInjection) {
        java.util.List<InjectionPoint> points = new java.util.ArrayList<>();
        if (req == null || req.request() == null) return points;

        String url = req.request().url();
        int qIdx = url.indexOf('?');

        // Query 参数
        if (qIdx >= 0) {
            String query = url.substring(qIdx + 1);
            parseParams(query, points, "query");
        }

        // POST Body 参数
        String method = req.request().method();
        String contentType = req.request().headerValue("Content-Type");
        if (("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method))
                && contentType != null) {
            String body = req.request().bodyToString();
            if (body != null && !body.isEmpty()) {
                if (contentType.contains("application/x-www-form-urlencoded")) {
                    parseParams(body, points, "body");
                } else if (contentType.contains("multipart/form-data")) {
                    String boundary = extractMultipartBoundary(contentType);
                    if (boundary != null) {
                        parseMultipartBody(body, boundary, points);
                    } else {
                        parseParams(body, points, "body");
                    }
                } else if (contentType.contains("application/json")) {
                    parseJsonBody(body, points, body);
                }
            }
        }

        // Cookie 参数（仅在开关开启时提取）
        if (enableCookieInjection) {
            String cookieHeader = req.request().headerValue("Cookie");
            if (cookieHeader != null && !cookieHeader.isEmpty()) {
                parseCookieParams(cookieHeader, points);
            }
        }

        return points;
    }

    /**
     * 提取 multipart/form-data 的 boundary
     */
    private static String extractMultipartBoundary(String contentType) {
        for (String part : contentType.split(";")) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase().startsWith("boundary=")) {
                return trimmed.substring("boundary=".length());
            }
        }
        return null;
    }

    /**
     * 解析 multipart/form-data body
     * 提取每个 part 的 name 和 value（忽略文件上传）
     */
    private static void parseMultipartBody(String body, String boundary, java.util.List<InjectionPoint> points) {
        if (boundary == null || body == null) return;
        String delimiter = "--" + boundary;
        String[] parts = body.split(delimiter);
        for (String part : parts) {
            if (part.trim().isEmpty() || part.trim().equals("--")) continue;
            // 提取 Content-Disposition 中的 name
            java.util.regex.Matcher nameMatcher = java.util.regex.Pattern.compile(
                    "name=\"([^\"]+)\"").matcher(part);
            if (nameMatcher.find()) {
                String name = nameMatcher.group(1);
                // 检查是否是文件上传（Content-Disposition 中有 filename=）
                java.util.regex.Matcher fileMatcher = java.util.regex.Pattern.compile(
                        "filename=\"").matcher(part);
                if (!fileMatcher.find()) {
                    // 非文件字段，提取 value（header 和 body 之间的空行之后）
                    int bodyStart = part.indexOf("\r\n\r\n");
                    String value = bodyStart >= 0
                            ? part.substring(bodyStart + 4).trim()
                            : "";
                    // 移除末尾的 --boundary
                    if (value.endsWith("\r\n--")) {
                        value = value.substring(0, value.length() - 4);
                    } else if (value.endsWith("--")) {
                        value = value.substring(0, value.length() - 2);
                    }
                    value = value.replace("\r\n", ""); // 去掉换行
                    points.add(new InjectionPoint(name, value, "body"));
                }
            }
        }
    }

    /**
     * JSON body 解析（递归下降法，正确处理嵌套/转义/空格）
     * 提取所有叶子节点的 key-value 作为注入点
     * 支持嵌套结构，将路径作为参数名（如 user.name）
     * paramType 统一设为 "json"，rawJson 保存完整原始 JSON 字符串
     */
    private static void parseJsonBody(String json, java.util.List<InjectionPoint> points, String rawJson) {
        if (json == null || json.trim().isEmpty()) return;
        try {
            JsonParser parser = new JsonParser(json.trim());
            parser.parseValue("", points, rawJson);
        } catch (Exception e) {
            // JSON 解析失败，静默忽略
        }
    }

    /**
     * 轻量级 JSON 解析器（递归下降）
     * 只提取叶子节点的 key-value 对，忽略数组元素
     */
    private static class JsonParser {
        private final String json;
        private int pos;

        JsonParser(String json) {
            this.json = json;
            this.pos = 0;
        }

        void parseValue(String key, java.util.List<InjectionPoint> points, String rawJson) {
            skipWhitespace();
            if (pos >= json.length()) return;

            char c = json.charAt(pos);

            if (c == '{') {
                parseObject(key, points, rawJson);
            } else if (c == '[') {
                parseArray(points, rawJson);
            } else if (c == '"') {
                String str = parseString();
                if (!key.isEmpty()) {
                    points.add(new InjectionPoint(key, str, "json", rawJson));
                }
            } else {
                // number / boolean / null
                String literal = parseLiteral();
                if (!key.isEmpty()) {
                    points.add(new InjectionPoint(key, literal, "json", rawJson));
                }
            }
        }

        void parseObject(String prefix, java.util.List<InjectionPoint> points, String rawJson) {
            expect('{');
            skipWhitespace();
            if (pos < json.length() && json.charAt(pos) == '}') {
                pos++; // empty object
                return;
            }

            while (pos < json.length()) {
                skipWhitespace();
                if (pos >= json.length()) break;
                if (json.charAt(pos) == '}') { pos++; break; }

                // parse key
                String memberKey = parseString();
                String fullKey = prefix.isEmpty() ? memberKey : prefix + "." + memberKey;

                skipWhitespace();
                expect(':');
                skipWhitespace();

                // parse value
                parseValue(fullKey, points, rawJson);

                skipWhitespace();
                if (pos < json.length() && json.charAt(pos) == ',') {
                    pos++; // consume comma
                }
            }
        }

        void parseArray(java.util.List<InjectionPoint> points, String rawJson) {
            expect('[');
            skipWhitespace();
            if (pos < json.length() && json.charAt(pos) == ']') {
                pos++; // empty array
                return;
            }

            while (pos < json.length()) {
                skipWhitespace();
                if (pos >= json.length()) break;
                if (json.charAt(pos) == ']') { pos++; break; }

                // Skip array elements (no key to attach)
                skipOneValue();

                skipWhitespace();
                if (pos < json.length() && json.charAt(pos) == ',') {
                    pos++;
                }
            }
        }

        /** Skip one JSON value without extracting (for array elements) */
        void skipOneValue() {
            skipWhitespace();
            if (pos >= json.length()) return;
            char c = json.charAt(pos);
            if (c == '"') {
                parseString(); // consume string
            } else if (c == '{') {
                parseObject("", new java.util.ArrayList<>(), null); // discard
            } else if (c == '[') {
                parseArray(new java.util.ArrayList<>(), null); // discard
            } else {
                parseLiteral(); // consume number/bool/null
            }
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < json.length()) {
                char c = json.charAt(pos);
                if (c == '\\') {
                    pos++;
                    if (pos >= json.length()) break;
                    char next = json.charAt(pos);
                    switch (next) {
                        case '"':  sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/':  sb.append('/'); break;
                        case 'n':  sb.append('\n'); break;
                        case 't':  sb.append('\t'); break;
                        case 'r':  sb.append('\r'); break;
                        case 'b':  sb.append('\b'); break;
                        case 'f':  sb.append('\f'); break;
                        case 'u':
                            // unicode escape
                            if (pos + 4 < json.length()) {
                                String hex = json.substring(pos + 1, pos + 5);
                                try { sb.append((char) Integer.parseInt(hex, 16)); } catch (NumberFormatException ignored) {}
                                pos += 4;
                            }
                            break;
                        default: sb.append(next); break;
                    }
                    pos++;
                } else if (c == '"') {
                    pos++; // consume closing quote
                    break;
                } else {
                    sb.append(c);
                    pos++;
                }
            }
            return sb.toString();
        }

        String parseLiteral() {
            int start = pos;
            while (pos < json.length()) {
                char c = json.charAt(pos);
                if (c == ',' || c == '}' || c == ']' || Character.isWhitespace(c)) break;
                pos++;
            }
            return json.substring(start, pos);
        }

        void skipWhitespace() {
            while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) pos++;
        }

        void expect(char expected) {
            if (pos < json.length() && json.charAt(pos) == expected) {
                pos++;
            }
            // tolerant: don't throw on mismatch
        }
    }

    /**
     * 解析 Cookie 参数
     */
    private static void parseCookieParams(String cookieHeader, java.util.List<InjectionPoint> points) {
        String[] cookies = cookieHeader.split(";\\s*");
        for (String cookie : cookies) {
            String trimmed = cookie.trim();
            if (trimmed.isEmpty()) continue;
            String[] kv = trimmed.split("=", 2);
            if (kv.length == 2) {
                String name = kv[0].trim();
                String value = kv[1].trim();
                if (!name.isEmpty()) {
                    points.add(new InjectionPoint(name, value, "cookie"));
                }
            }
        }
    }

    private static void parseParams(String raw, java.util.List<InjectionPoint> points, String type) {
        if (raw == null || raw.isEmpty()) return;
        String[] pairs = raw.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                String name = java.net.URLDecoder.decode(kv[0], java.nio.charset.StandardCharsets.UTF_8);
                String value = java.net.URLDecoder.decode(kv[1], java.nio.charset.StandardCharsets.UTF_8);
                points.add(new InjectionPoint(name, value, type));
            } else if (kv.length == 1 && !kv[0].isEmpty()) {
                String name = java.net.URLDecoder.decode(kv[0], java.nio.charset.StandardCharsets.UTF_8);
                points.add(new InjectionPoint(name, "", type));
            }
        }
    }

    /**
     * 检查文件扩展名是否应排除
     */
    public static boolean shouldExcludeExtension(String url, Set<String> excludedExtensions) {
        if (excludedExtensions == null || excludedExtensions.isEmpty()) return false;
        // 提取路径最后一段
        String path = url;
        int qIdx = url.indexOf('?');
        if (qIdx >= 0) path = url.substring(0, qIdx);
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash >= 0) path = path.substring(lastSlash + 1);

        int dotIdx = path.lastIndexOf('.');
        if (dotIdx < 0) return false;
        String ext = path.substring(dotIdx + 1).toLowerCase();
        return excludedExtensions.contains(ext);
    }

    /**
     * 对一个注入点执行完整的检测链（v5.6 重构）
     *
     * 核心原则：勾选即执行，不受前置结果影响。
     * 所有勾选的检测器都会执行，任一检测器发现可疑即为可疑。
     *
     * @param timeoutMs 单请求超时（毫秒）
     * @param delayMs   请求间延迟（毫秒）
     */
    public static ProbeResult runDetectionChain(MontoyaApi api, String url,
                                                InjectionPoint point,
                                                HttpRequestResponse baseReq,
                                                boolean enableStringBlind,
                                                boolean enableNumeric,
                                                boolean enableOrderBy,
                                                boolean enableTimeBlind,
                                                int timeoutMs,
                                                int delayMs) {
        // 用于收集所有检测结果
        java.util.List<ProbeResult> allResults = new java.util.ArrayList<>();
        ProbeResult.DetectorType primaryType = ProbeResult.DetectorType.STRING_BLIND;

        // 1) 字符型布尔盲注（勾选时执行）
        if (enableStringBlind) {
            StringBlindDetector stringDetector = new StringBlindDetector();
            stringDetector.setTimeoutMs(timeoutMs);
            stringDetector.setDelayMs(delayMs);
            ProbeResult stringResult = stringDetector.detect(
                    api, url, point.paramName(), point.paramValue(), baseReq, point.paramType());
            allResults.add(stringResult);
        }

        // 2) 数字型注入（勾选时执行，对所有参数，不再限制纯数字）
        if (enableNumeric) {
            NumericDetector numericDetector = new NumericDetector();
            numericDetector.setTimeoutMs(timeoutMs);
            numericDetector.setDelayMs(delayMs);
            ProbeResult numericResult = numericDetector.detect(
                    api, url, point.paramName(), point.paramValue(), baseReq, point.paramType());
            allResults.add(numericResult);
        }

        // 3) Order By 注入（勾选时执行，对所有参数，不再限制参数名）
        if (enableOrderBy) {
            OrderByDetector orderDetector = new OrderByDetector();
            orderDetector.setTimeoutMs(timeoutMs);
            orderDetector.setDelayMs(delayMs);
            ProbeResult orderResult = orderDetector.detect(
                    api, url, point.paramName(), point.paramValue(), baseReq, point.paramType());
            allResults.add(orderResult);
        }

        // 4) 时间盲注（勾选时执行）
        if (enableTimeBlind) {
            TimeBlindDetector timeDetector = new TimeBlindDetector();
            timeDetector.setTimeoutMs(timeoutMs);
            timeDetector.setDelayMs(delayMs);
            ProbeResult timeResult = timeDetector.detect(
                    api, url, point.paramName(), point.paramValue(), baseReq, point.paramType());
            allResults.add(timeResult);
        }

        // ===== 综合判定 =====
        // 任一检测器发现可疑即为可疑
        // 优先返回第一个可疑结果
        for (ProbeResult result : allResults) {
            if (result.getStatus() == ProbeResult.Status.SUSPICIOUS) {
                return result;
            }
        }

        // 所有检测均未发现可疑，返回 SAFE
        ProbeResult safeResult = new ProbeResult(url, point.paramName(), point.paramValue(),
                ProbeResult.DetectorType.STRING_BLIND);
        safeResult.setStatus(ProbeResult.Status.SAFE);
        return safeResult;
    }
}
