package com.example.burp.sqli.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * 右键菜单提供者
 *
 * 在各处（Proxy History, Repeater, SiteMap 等）右键请求时，
 * 显示"Send to SQLi Probe"菜单项，将选中请求发送到探测队列。
 *
 * 支持两种来源：
 *  1. Proxy History / SiteMap 等列表视图中多选请求后右键 → selectedRequestResponses()
 *  2. Repeater / Proxy 消息编辑器中右键 → messageEditorRequestResponse()（编辑器内无选中行时的 fallback）
 */
public class SqliProbeContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final Consumer<List<HttpRequestResponse>> onRequestReceived;

    /**
     * @param api               BurpSuite MontoyaApi
     * @param onRequestReceived  接收到用户发送的请求后的回调，参数为完整的 HttpRequestResponse 列表
     */
    public SqliProbeContextMenu(MontoyaApi api, Consumer<List<HttpRequestResponse>> onRequestReceived) {
        this.api = api;
        this.onRequestReceived = onRequestReceived;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // ① 优先：列表视图中选中的多条请求（Proxy History、SiteMap 等）
        List<HttpRequestResponse> selected = event.selectedRequestResponses();

        // ② Fallback：消息编辑器（Repeater / Proxy 请求框）中直接右键
        //    此时 selectedRequestResponses() 返回空，需从 messageEditorRequestResponse() 获取
        if (selected == null || selected.isEmpty()) {
            Optional<MessageEditorHttpRequestResponse> editorRR = event.messageEditorRequestResponse();
            if (editorRR.isPresent()) {
                HttpRequestResponse rr = editorRR.get().requestResponse();
                if (rr != null && rr.request() != null) {
                    selected = List.of(rr);
                }
            }
        }

        if (selected == null || selected.isEmpty()) {
            return menuItems;
        }

        // 构建菜单项标签
        String label = selected.size() == 1
                ? "Send to SQLi Probe"
                : "Send to SQLi Probe (" + selected.size() + " requests)";

        JMenuItem sendItem = new JMenuItem(label);
        sendItem.setIcon(createIcon());
        final List<HttpRequestResponse> finalSelected = selected;
        sendItem.addActionListener(e -> sendSelectedRequests(finalSelected));
        menuItems.add(sendItem);

        return menuItems;
    }

    /**
     * 发送选中的请求到队列
     */
    private void sendSelectedRequests(List<HttpRequestResponse> selected) {
        List<HttpRequestResponse> validItems = new ArrayList<>();
        for (HttpRequestResponse rr : selected) {
            if (rr.request() != null) {
                validItems.add(rr);
            }
        }
        if (!validItems.isEmpty()) {
            api.logging().logToOutput("[SQLi Probe] Received " + validItems.size() + " request(s) from context menu.");
            onRequestReceived.accept(validItems);
        }
    }

    private Icon createIcon() {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(52, 152, 219));
                g2.setStroke(new BasicStroke(2));
                g2.drawOval(x + 1, y + 1, 10, 10);
                g2.drawLine(x + 9, y + 9, x + 15, y + 15);
                g2.setColor(Color.RED);
                g2.setFont(new Font("SansSerif", Font.BOLD, 10));
                g2.drawString("!", x + 5, y + 11);
                g2.dispose();
            }

            @Override
            public int getIconWidth() { return 16; }

            @Override
            public int getIconHeight() { return 16; }
        };
    }
}
