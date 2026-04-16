package com.example.burp.sqli.detector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.example.burp.sqli.core.ProbeResult;

/**
 * 检测器接口
 * 所有检测器实现此接口，执行特定类型的 SQL 注入探测。
 *
 * 子类可通过 setTimeoutMs/setDelayMs 配置请求超时和延迟。
 */
public interface Detector {

    /**
     * 执行探测
     *
     * @param api       BurpSuite MontoyaApi
     * @param url       目标 URL
     * @param paramName 参数名
     * @param paramValue 参数原始值
     * @param baseReq   原始请求（用于复制 service 等信息）
     * @param paramType 参数类型 "query" / "body" / "cookie"
     * @return 探测结果（包含所有 entry）
     */
    ProbeResult detect(MontoyaApi api, String url, String paramName,
                       String paramValue, HttpRequestResponse baseReq, String paramType);

    /**
     * 设置单请求超时（毫秒）。默认 10000ms。
     * 子类可覆写以在 sendRequest 时应用超时。
     */
    default void setTimeoutMs(int timeoutMs) {}

    /**
     * 设置请求间延迟（毫秒）。默认 0ms。
     * 子类可覆写以在每次 sendRequest 前等待。
     */
    default void setDelayMs(int delayMs) {}
}
