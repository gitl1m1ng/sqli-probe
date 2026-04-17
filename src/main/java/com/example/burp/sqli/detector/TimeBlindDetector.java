package com.example.burp.sqli.detector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.example.burp.sqli.core.ProbeResult;

import java.util.List;

/**
 * 时间盲注检测器（v5.8.7）
 *
 * Payload（全部尝试，综合判定）：
 *   - poc1: ' XOR SLEEP(5) XOR '  （字符型注入环境）
 *   - poc2: 1*SLEEP(5)            （数字型注入环境，仅对参数值为数字时使用）
 *   - poc3: SLEEP(5)              （通用，不依赖闭合）
 *
 * 判定：所有 Payload 都尝试后，任一触发延迟或超时 → 可疑
 */
public class TimeBlindDetector implements Detector {

    private static final long TIME_THRESHOLD_MS = 4000; // 4 秒阈值

    protected int timeoutMs = 60000; // 时间盲注默认 60s 超时（需要等待 SLEEP）
    protected int delayMs = 0;

    // 数字型参数：尝试所有三个 Payload
    // 非数字型参数：跳过 poc2 (1*SLEEP(5))
    // 注：POC_LABELS 需要与 SLEEP_PAYLOADS 长度一致
    private static final String[] SLEEP_PAYLOADS_ALL = {
            "' XOR SLEEP(5) XOR '",  // poc1
            "1*SLEEP(5)",             // poc2
            "SLEEP(5)"                // poc3
    };
    private static final String[] SLEEP_PAYLOADS_NON_NUMERIC = {
            "' XOR SLEEP(5) XOR '",  // poc1
            "SLEEP(5)"                // poc2（跳过数字型 payload）
    };
    private static final String[] POC_LABELS_ALL = {"poc1", "poc2", "poc3"};
    private static final String[] POC_LABELS_NON_NUMERIC = {"poc1", "poc2"};  // 与 NON_NUMERIC payload 数量一致

    @Override
    public void setTimeoutMs(int timeoutMs) { this.timeoutMs = Math.max(10000, timeoutMs); } // 至少 10s
    @Override
    public void setDelayMs(int delayMs) { this.delayMs = Math.max(0, delayMs); }

    @Override
    public ProbeResult detect(MontoyaApi api, String url, String paramName,
                              String paramValue, HttpRequestResponse baseReq, String paramType) {
        ProbeResult result = new ProbeResult(url, paramName, paramValue, ProbeResult.DetectorType.TIME_BLIND);

        api.logging().logToOutput(String.format(
                "[SQLi Probe] TimeBlind start: param=%s, value=%s, timeout=%ds",
                paramName, paramValue, timeoutMs / 1000));

        // 1) baseline: 发送原始请求获取基准响应时间
        HttpRequest reqBase = StringBlindDetector.buildRequestWithParam(baseReq, paramName, paramValue, paramType);
        ProbeResult.ProbeEntry eBase = StringBlindDetector.sendAndRecord(
                api, "baseline", paramValue, reqBase, 30000, 0); // baseline 30s 超时
        result.addEntry(eBase);

        long baselineTime = eBase.getResponseTimeMs();
        long threshold = baselineTime + TIME_THRESHOLD_MS;
        api.logging().logToOutput(String.format(
                "[SQLi Probe] TimeBlind baseline: param=%s, value=%s, baselineTime=%dms",
                paramName, paramValue, baselineTime));

        // 2) 根据参数类型选择 Payload
        // 数字型参数：尝试所有三个 Payload
        // 非数字型参数：跳过 poc2 (1*SLEEP(5))
        boolean isNumeric = NumericDetector.isNumericParam(paramValue);
        String[] payloads = isNumeric ? SLEEP_PAYLOADS_ALL : SLEEP_PAYLOADS_NON_NUMERIC;
        String[] pocLabels = isNumeric ? POC_LABELS_ALL : POC_LABELS_NON_NUMERIC;

        if (!isNumeric) {
            api.logging().logToOutput(String.format(
                    "[SQLi Probe] TimeBlind: param value is non-numeric, skipping numeric payload (1*SLEEP(5))"));
        }

        boolean foundInjection = false;
        for (int i = 0; i < payloads.length; i++) {
            String payload = payloads[i];
            String pocLabel = pocLabels[i] + ": " + payload;

            api.logging().logToOutput(String.format(
                    "[SQLi Probe] TimeBlind sending: %s, payload=%s",
                    pocLabel, payload));

            try {
                HttpRequest reqPoc = StringBlindDetector.buildRequestWithParam(baseReq, paramName, payload, paramType);
                ProbeResult.ProbeEntry entry = StringBlindDetector.sendAndRecord(
                        api, pocLabel, payload, reqPoc, timeoutMs, delayMs);
                result.addEntry(entry);

                // 检查是否超时或响应延迟
                boolean isTimeout = entry.getLabel() != null && entry.getLabel().contains("TIMEOUT");
                long respTime = entry.getResponseTimeMs();

                api.logging().logToOutput(String.format(
                        "[SQLi Probe] TimeBlind response: %s, respTime=%dms, threshold=%dms, baseline=%dms, isTimeout=%s",
                        pocLabel, respTime, threshold, baselineTime, isTimeout));

                if (isTimeout || respTime > threshold) {
                    // 任一 Payload 触发即为可疑
                    result.setStatus(ProbeResult.Status.SUSPICIOUS);
                    api.logging().logToOutput(String.format(
                            "[SQLi Probe] TimeBlind TRIGGERED: %s, respTime=%dms",
                            pocLabel, respTime));
                    foundInjection = true;
                    // 继续尝试后续 Payload（不 break）
                }
            } catch (Exception e) {
                // v6.0 修复：捕获异常，避免单次请求失败导致整个检测中断
                // v1.0.1 修复：保留请求对象，便于用户查看
                api.logging().logToOutput(String.format(
                        "[SQLi Probe] TimeBlind ERROR in %s: %s - continuing with next payload",
                        pocLabel, e.getClass().getSimpleName(), e.getMessage()));
                // 添加一个错误 entry 以便记录（保留请求对象）
                HttpRequest reqForError = null;
                try {
                    reqForError = StringBlindDetector.buildRequestWithParam(baseReq, paramName, payload, paramType);
                } catch (Exception ignored) {}
                result.addEntry(new ProbeResult.ProbeEntry(
                        pocLabel + " (ERROR)", payload,
                        reqForError != null ? burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(reqForError, null) : null,
                        0,
                        java.util.List.of("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage())));
            }
        }

        if (foundInjection) {
            api.logging().logToOutput("[SQLi Probe] TimeBlind SUSPICIOUS: at least one payload triggered delay");
        } else {
            result.setStatus(ProbeResult.Status.SAFE);
            api.logging().logToOutput(String.format(
                    "[SQLi Probe] TimeBlind SAFE: all payloads returned normal response time (threshold=%dms)",
                    threshold));
        }

        return result;
    }
}
