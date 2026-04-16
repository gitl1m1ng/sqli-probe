package com.example.burp.sqli.detector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.example.burp.sqli.core.ProbeResult;

import java.util.List;

/**
 * 数字型注入检测器
 *
 * 基于原始参数值（如 5、10、123）动态构造 Payload：
 *   baseline: 原始值（如 5）
 *   poc1:     原始值*1（如 5*1）→ 乘以 1，SQL 引擎计算后结果不变（true 验证）
 *   poc2:     原始值*0（如 5*0）→ 乘以 0，SQL 引擎计算后结果变为 0（false 验证）
 *
 * 判定逻辑（v5.4 最终版）：
 *   必要条件：*1 payload（poc1）与 baseline 响应相同
 *   且 *0 payload（poc2）与 baseline 响应不同
 *   → 标记为"可疑 - 数字型注入"
 *
 * "响应相同"的判定：相似度 > 0.95 且 状态码相同
 * "响应不同"的判定：相似度 < 0.95 或 状态码不同
 */
public class NumericDetector implements Detector {

    protected int timeoutMs = 10000;
    protected int delayMs = 0;

    @Override
    public void setTimeoutMs(int timeoutMs) { this.timeoutMs = Math.max(1000, timeoutMs); }
    @Override
    public void setDelayMs(int delayMs) { this.delayMs = Math.max(0, delayMs); }

    @Override
    public ProbeResult detect(MontoyaApi api, String url, String paramName,
                              String paramValue, HttpRequestResponse baseReq, String paramType) {
        ProbeResult result = new ProbeResult(url, paramName, paramValue, ProbeResult.DetectorType.NUMERIC);

        // 1) baseline: 直接使用引擎缓存的原始响应（不重复发送）
        ProbeResult.ProbeEntry e0 = new ProbeResult.ProbeEntry(
                "baseline: " + paramValue, paramValue, baseReq, 0, List.of());
        result.addEntry(e0);

        // 2) poc1: 原始值*1（true 验证：乘以 1 结果不变）
        String poc1 = paramValue + "*1";
        HttpRequest req1 = StringBlindDetector.buildRequestWithParam(baseReq, paramName, poc1, paramType);
        ProbeResult.ProbeEntry e1 = StringBlindDetector.sendAndRecord(
                api, "poc1: " + paramValue + "*1", poc1, req1, timeoutMs, delayMs);
        result.addEntry(e1);

        // 3) poc2: 原始值*0
        String poc2 = paramValue + "*0";
        HttpRequest req2 = StringBlindDetector.buildRequestWithParam(baseReq, paramName, poc2, paramType);
        ProbeResult.ProbeEntry e2 = StringBlindDetector.sendAndRecord(
                api, "poc2: " + paramValue + "*0", poc2, req2, timeoutMs, delayMs);
        result.addEntry(e2);

        // 判定
        String body0 = StringBlindDetector.getResponseBody(e0);
        String body1 = StringBlindDetector.getResponseBody(e1);
        String body2 = StringBlindDetector.getResponseBody(e2);

        int len0 = body0.length();
        double lenDiff1 = len0 > 0 ? Math.abs(body1.length() - len0) * 100.0 / len0 : 0;
        double lenDiff2 = len0 > 0 ? Math.abs(body2.length() - len0) * 100.0 / len0 : 0;

        double sim01 = StringBlindDetector.similarity(body0, body1);
        double sim02 = StringBlindDetector.similarity(body0, body2);

        // ===== 数字型注入判定逻辑（v5.4 最终版） =====
        //
        // 规则：当且仅当同时满足以下两个条件时，判定为数字型注入：
        //   1. *1 payload（poc1）与 baseline 响应相同 → 参数被 SQL 引擎计算，结果不变
        //   2. *0 payload（poc2）与 baseline 响应不同 → 参数被 SQL 引擎计算，结果归零
        //
        // "响应相同"的判定：相似度 > 0.95 且 状态码相同
        // "响应不同"的判定：相似度 < 0.95 或 状态码不同

        int status0 = e0.getStatusCode();
        int status1 = e1.getStatusCode();
        int status2 = e2.getStatusCode();

        // poc1 与 baseline 相同
        boolean poc1SameBaseline = sim01 > 0.95 && status1 == status0;
        // poc2 与 baseline 不同
        boolean poc2DiffBaseline = sim02 < 0.95 || status2 != status0;

        if (poc1SameBaseline && poc2DiffBaseline) {
            result.setStatus(ProbeResult.Status.SUSPICIOUS);
        } else {
            result.setStatus(ProbeResult.Status.SAFE);
        }

        return result;
    }

    /**
     * 判断参数值是否为纯数字（仅对纯数字参数执行数字型检测）
     */
    public static boolean isNumericParam(String value) {
        if (value == null || value.isEmpty()) return false;
        return value.matches("^\\d+$");
    }
}
