package com.example.burp.sqli;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.core.Registration;
import com.example.burp.sqli.ui.ProbeTab;
import com.example.burp.sqli.ui.SqliProbeContextMenu;

import java.util.List;

/**
 * SQLi Probe - BurpSuite SQL 注入辅助验证插件
 *
 * 入口类：注册自定义 Suite Tab、右键菜单。
 *
 * 核心定位：辅助验证工具，不自动定论，结果由人工判断。
 */
public class SqliProbeExtension implements BurpExtension {

    private ProbeTab probeTab;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("SQLi Probe");
        api.extension().registerUnloadingHandler(() -> {
            if (probeTab != null) {
                probeTab.cleanup();
            }
            api.logging().logToOutput("[SQLi Probe] Plugin unloaded.");
        });

        // 创建并注册 UI Tab
        probeTab = new ProbeTab(api);
        api.userInterface().registerSuiteTab("SQLi Probe", probeTab);

        // 注册右键菜单：在 Proxy / Repeater / SiteMap 等处右键请求 → "Send to SQLi Probe"
        api.userInterface().registerContextMenuItemsProvider(
                new SqliProbeContextMenu(api, rrList ->
                        probeTab.getEngine().addRequestResponses(rrList, "右键"))
        );

        api.logging().logToOutput("[SQLi Probe] Plugin loaded successfully. Tab registered.");
        api.logging().logToOutput("[SQLi Probe] Usage:");
        api.logging().logToOutput("  - Right-click requests → 'Send to SQLi Probe'");
        api.logging().logToOutput("  - Use 'Load from Proxy History' button in the tab");
    }
}
