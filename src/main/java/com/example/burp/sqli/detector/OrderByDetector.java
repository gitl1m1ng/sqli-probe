package com.example.burp.sqli.detector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.example.burp.sqli.core.ProbeResult;

import java.util.List;
import java.util.Set;

/**
 * Order 类型注入检测器
 *
 * Payload:
 *   baseline: 原始值        → 原始排序
 *   poc1:     原始值,0      → 追加排序（辅助验证）
 *   poc2:     原始值,999999 → 追加排序（超大分页差异）
 *
 * 仅对参数名包含 order/sort/by 等关键字的参数执行。
 * 判定：resp(,0) 与 baseline 相同 且 resp(,999999) 与 baseline 不同 → 可能存在注入
 *
 * "响应不同"的判定：相似度 < 0.95 或 状态码不同
 */
public class OrderByDetector implements Detector {

    protected int timeoutMs = 10000;
    protected int delayMs = 0;

    @Override
    public void setTimeoutMs(int timeoutMs) { this.timeoutMs = Math.max(1000, timeoutMs); }
    @Override
    public void setDelayMs(int delayMs) { this.delayMs = Math.max(0, delayMs); }

    private static final Set<String> ORDER_KEYWORDS = Set.of(
            "order", "sort", "by", "orderby", "sortby", "排序", "排序字段"
    );

    /**
     * 判断参数名是否疑似 ORDER BY 相关
     */
    public static boolean isOrderParam(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase();
        for (String kw : ORDER_KEYWORDS) {
            if (lower.contains(kw)) return true;
        }
        return false;
    }

    @Override
    public ProbeResult detect(MontoyaApi api, String url, String paramName,
                              String paramValue, HttpRequestResponse baseReq, String paramType) {
        ProbeResult result = new ProbeResult(url, paramName, paramValue, ProbeResult.DetectorType.ORDER_BY);

        // 1) baseline: 直接使用引擎缓存的原始响应（不重复发送）
        ProbeResult.ProbeEntry e0 = new ProbeResult.ProbeEntry(
                "baseline: " + paramValue, paramValue, baseReq, 0, List.of());
        result.addEntry(e0);

        // 2) poc1: 原始值,1（ASC 升序）
        String poc1 = paramValue + ",1";
        HttpRequest req1 = StringBlindDetector.buildRequestWithParam(baseReq, paramName, poc1, paramType);
        ProbeResult.ProbeEntry e1 = StringBlindDetector.sendAndRecord(
                api, "poc1: " + paramValue + ",1", poc1, req1, timeoutMs, delayMs);
        result.addEntry(e1);

        // 3) poc2: 原始值,999999（超大分页，更明显）
        String poc2 = paramValue + ",999999";
        HttpRequest req2 = StringBlindDetector.buildRequestWithParam(baseReq, paramName, poc2, paramType);
        ProbeResult.ProbeEntry e2 = StringBlindDetector.sendAndRecord(
                api, "poc2: " + paramValue + ",999999", poc2, req2, timeoutMs, delayMs);
        result.addEntry(e2);

        // 判定
        String body0 = StringBlindDetector.getResponseBody(e0);
        String body1 = StringBlindDetector.getResponseBody(e1);
        String body2 = StringBlindDetector.getResponseBody(e2);

        double sim01 = StringBlindDetector.similarity(body0, body1);
        double sim02 = StringBlindDetector.similarity(body0, body2);

        // 状态码
        int status0 = e0.getStatusCode();
        int status1 = e1.getStatusCode();
        int status2 = e2.getStatusCode();

        // 响应不同 = 相似度<0.95 或 状态码不同
        boolean poc1Diff = sim01 < 0.95 || status1 != status0;
        boolean poc2Diff = sim02 < 0.95 || status2 != status0;

        // v5.8.3: 判定逻辑改为：poc1与baseline相同 且 poc2与baseline不同 → 可疑
        // ,1 追加排序通常响应相同（升序默认），但 ,999999 超大分页会导致响应不同
        // 如果 poc1 就不同（追加排序本身改变了响应），则可能是参数化值有问题，不判定为注入
        if (!poc1Diff && poc2Diff) {
            result.setStatus(ProbeResult.Status.SUSPICIOUS);
        } else {
            result.setStatus(ProbeResult.Status.SAFE);
        }

        return result;
    }
}
