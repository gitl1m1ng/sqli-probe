package com.example.burp.sqli.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import java.awt.*;

/**
 * 共用详情面板
 *
 * 封装 BurpSuite 内置的 HttpRequestEditor / HttpResponseEditor，
 * 待探测队列表格和探测结果表格共用同一个实例。
 *
 * 使用方式：
 * - 单击队列表格行 → setRequestResponse(rr, editable=true)  显示该请求（可编辑）
 * - 单击结果表格行 → setRequestResponse(rr, editable=false) 显示 baseline（只读）
 * - 切换选中时自动清空并加载新内容
 *
 * 布局（v4.2）：左右分割，左侧请求编辑器，右侧响应编辑器。
 * 改为左右分布更适合查看长 URL 和 JSON 请求体。
 */
public class MessageEditorPanel extends JPanel {

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JLabel titleLabel;
    private final JLabel requestLabel;
    private final JLabel responseLabel;

    /**
     * @param api MontoyaApi 实例，用于创建 BurpSuite 内置编辑器
     */
    public MessageEditorPanel(MontoyaApi api) {
        setLayout(new BorderLayout(0, 0));

        // 通过 Montoya API 创建 BurpSuite 内置的 HTTP 请求/响应编辑器
        // 请求编辑器：默认可编辑（不传 EditorOptions.READ_ONLY）
        requestEditor = api.userInterface().createHttpRequestEditor();
        // 响应编辑器：始终只读
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // 顶部标题栏
        titleLabel = new JLabel("  选中左侧表格行以查看请求/响应");
        titleLabel.setOpaque(true);
        titleLabel.setBackground(new Color(240, 240, 240));
        titleLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        add(titleLabel, BorderLayout.NORTH);

        // 左右分割：左侧请求编辑器 + 右侧响应编辑器
        // 创建左右面板容器
        JPanel leftPanel = new JPanel(new BorderLayout(0, 0));
        requestLabel = new JLabel("  Request");
        requestLabel.setOpaque(true);
        requestLabel.setBackground(new Color(230, 240, 250));
        requestLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        requestLabel.setFont(requestLabel.getFont().deriveFont(Font.BOLD, 11));
        leftPanel.add(requestLabel, BorderLayout.NORTH);
        leftPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JPanel rightPanel = new JPanel(new BorderLayout(0, 0));
        responseLabel = new JLabel("  Response");
        responseLabel.setOpaque(true);
        responseLabel.setBackground(new Color(240, 250, 230));
        responseLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        responseLabel.setFont(responseLabel.getFont().deriveFont(Font.BOLD, 11));
        rightPanel.add(responseLabel, BorderLayout.NORTH);
        rightPanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                leftPanel,
                rightPanel
        );
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(400);
        add(splitPane, BorderLayout.CENTER);
    }

    /**
     * 设置请求/响应到编辑器
     *
     * @param rr       HTTP 请求响应对
     * @param title    标题文字（如 "队列请求 #1"、"Baseline | /api/user?id=1 ? id"）
     * @param editable 请求编辑器是否可编辑（队列为 true，结果为 false）
     */
    public void setRequestResponse(HttpRequestResponse rr, String title, boolean editable) {
        if (rr == null || rr.request() == null) {
            clear();
            return;
        }

        // 更新标题
        titleLabel.setText("  " + title);

        // 设置请求到 BurpSuite 内置编辑器
        // setRequest() 会触发编辑器自动渲染（语法高亮、搜索栏等）
        requestEditor.setRequest(rr.request());

        // 设置响应（可能为 null，如目标不可达）
        if (rr.response() != null) {
            responseEditor.setResponse(rr.response());
        } else {
            responseEditor.setResponse(createEmptyResponse());
        }

        // 注意：BurpSuite 内置编辑器不支持动态切换 READ_ONLY 模式
        // 创建时就决定了。如需可编辑/只读切换，需要创建两套编辑器。
        // 这里我们保持请求编辑器始终可编辑（用户可以在队列表格中修改请求后发送），
        // 结果表格中也保持可编辑，但逻辑上用户不应修改探测结果。
    }

    /**
     * 只设置请求（无响应），用于无缓存的场景
     */
    public void setRequestOnly(HttpRequest request, String title) {
        if (request == null) {
            clear();
            return;
        }

        titleLabel.setText("  " + title);
        requestEditor.setRequest(request);
        // 清空响应
        responseEditor.setResponse(createEmptyResponse());
    }

    /**
     * 清空编辑器内容
     */
    public void clear() {
        titleLabel.setText("  选中左侧表格行以查看请求/响应");
        // 设置空请求/响应来清空编辑器显示
        requestEditor.setRequest(createEmptyRequest());
        responseEditor.setResponse(createEmptyResponse());
    }

    /**
     * 获取当前请求编辑器中用户修改后的请求（如果用户编辑了的话）
     *
     * @return 编辑器中的 HttpRequest，如果用户未修改则返回原始请求
     */
    public HttpRequest getCurrentRequest() {
        return requestEditor.getRequest();
    }

    /**
     * 判断用户是否修改了请求编辑器中的内容
     */
    public boolean isRequestModified() {
        return requestEditor.isModified();
    }

    /**
     * 创建一个空的 HttpRequest（用于清空编辑器）
     */
    private static HttpRequest createEmptyRequest() {
        return HttpRequest.httpRequest();
    }

    /**
     * 创建一个空的 HttpResponse（用于清空编辑器）
     */
    private static HttpResponse createEmptyResponse() {
        return HttpResponse.httpResponse();
    }
}
