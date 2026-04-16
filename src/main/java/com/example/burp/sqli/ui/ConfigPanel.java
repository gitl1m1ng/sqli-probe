package com.example.burp.sqli.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * 配置面板（v4.1）
 *
 * 核心变更：
 *   - 新增 "Cookie 注入" 复选框，默认关闭
 *   - 移除 "从 Site Map 加载" 按钮（改为 SiteMap 右键菜单）
 *   - 按钮状态管理：根据引擎状态动态启用/禁用按钮
 *   - 配置变更时闪烁提示，让用户知道配置已更新
 */
public class ConfigPanel extends JPanel {

    private final JSpinner concurrencySpinner;
    private final JSpinner timeoutSpinner;
    private final JSpinner delaySpinner;
    private final JCheckBox onlyInScopeCheck;
    private final JTextField excludeExtField;

    private final JCheckBox enableStringBlindCheck;
    private final JCheckBox enableNumericCheck;
    private final JCheckBox enableOrderByCheck;
    private final JCheckBox enableTimeBlindCheck;
    private final JCheckBox enableCookieInjectionCheck;

    // 配置变更闪烁提示
    private final JLabel configFeedbackLabel;
    private final Timer feedbackTimer;
    private static final Color FEEDBACK_COLOR = new Color(40, 167, 69);

    public ConfigPanel() {
        setLayout(new BorderLayout(0, 4));
        setBorder(BorderFactory.createTitledBorder("配置"));

        // --- 顶部行：并发 + 超时 + 延迟 ---
        JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        topRow.add(new JLabel("并发:"));
        concurrencySpinner = new JSpinner(new SpinnerNumberModel(5, 1, 50, 1));
        concurrencySpinner.setPreferredSize(new Dimension(55, 25));
        topRow.add(concurrencySpinner);

        topRow.add(new JLabel("超时:"));
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 60, 1));
        topRow.add(timeoutSpinner);
        topRow.add(new JLabel("s"));

        topRow.add(new JLabel("延迟:"));
        delaySpinner = new JSpinner(new SpinnerNumberModel(0, 0, 10000, 100));
        delaySpinner.setPreferredSize(new Dimension(65, 25));
        topRow.add(delaySpinner);
        topRow.add(new JLabel("ms"));

        // 配置变更反馈标签
        configFeedbackLabel = new JLabel(" ");
        configFeedbackLabel.setFont(configFeedbackLabel.getFont().deriveFont(Font.BOLD, 11));
        configFeedbackLabel.setForeground(FEEDBACK_COLOR);
        topRow.add(Box.createHorizontalStrut(15));
        topRow.add(configFeedbackLabel);

        // 闪烁定时器：2秒后消失
        feedbackTimer = new Timer(2000, e -> {
            configFeedbackLabel.setText(" ");
        });
        feedbackTimer.setRepeats(false);

        add(topRow, BorderLayout.NORTH);

        // --- 中间行：过滤 ---
        JPanel midRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        onlyInScopeCheck = new JCheckBox("仅 In-Scope", false);
        midRow.add(onlyInScopeCheck);

        midRow.add(Box.createHorizontalStrut(10));

        midRow.add(new JLabel("排除扩展名:"));
        excludeExtField = new JTextField("jpg|png|gif|css|js|ico|woff|woff2|svg|ttf|eot", 30);
        midRow.add(excludeExtField);

        add(midRow, BorderLayout.CENTER);

        // --- 检测项行 ---
        JPanel detectRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        enableStringBlindCheck = new JCheckBox("字符型盲注", true);
        enableNumericCheck = new JCheckBox("数字型", true);
        enableOrderByCheck = new JCheckBox("Order型", true);
        enableTimeBlindCheck = new JCheckBox("时间盲注", false);
        enableCookieInjectionCheck = new JCheckBox("Cookie 注入", false);

        detectRow.add(new JLabel("检测项:"));
        detectRow.add(enableStringBlindCheck);
        detectRow.add(enableNumericCheck);
        detectRow.add(enableOrderByCheck);
        detectRow.add(enableTimeBlindCheck);
        detectRow.add(new JLabel("（默认关闭）"));

        detectRow.add(Box.createHorizontalStrut(10));

        detectRow.add(enableCookieInjectionCheck);
        detectRow.add(new JLabel("（默认关闭）"));

        add(detectRow, BorderLayout.SOUTH);

        // 为所有配置项添加变更监听
        addConfigChangeListeners();
    }

    /**
     * 为所有配置组件添加变更监听，触发闪烁反馈
     */
    private void addConfigChangeListeners() {
        Consumer<Object> onChange = o -> showFeedback("配置已更新（下次探测生效）");

        concurrencySpinner.addChangeListener(e -> onChange.accept(null));
        timeoutSpinner.addChangeListener(e -> onChange.accept(null));
        delaySpinner.addChangeListener(e -> onChange.accept(null));
        onlyInScopeCheck.addItemListener(e -> onChange.accept(null));
        enableStringBlindCheck.addItemListener(e -> onChange.accept(null));
        enableNumericCheck.addItemListener(e -> onChange.accept(null));
        enableOrderByCheck.addItemListener(e -> onChange.accept(null));
        enableTimeBlindCheck.addItemListener(e -> onChange.accept(null));
        enableCookieInjectionCheck.addItemListener(e -> onChange.accept(null));
        excludeExtField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { onChange.accept(null); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { onChange.accept(null); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { onChange.accept(null); }
        });
    }

    /**
     * 显示配置变更反馈
     */
    private void showFeedback(String text) {
        configFeedbackLabel.setText("✓ " + text);
        feedbackTimer.restart();
    }

    // --- Getter ---

    public int getConcurrency() { return (Integer) concurrencySpinner.getValue(); }
    public int getTimeout() { return (Integer) timeoutSpinner.getValue(); }
    public int getDelay() { return (Integer) delaySpinner.getValue(); }
    public boolean isOnlyInScope() { return onlyInScopeCheck.isSelected(); }
    public boolean isEnableStringBlind() { return enableStringBlindCheck.isSelected(); }
    public boolean isEnableNumeric() { return enableNumericCheck.isSelected(); }
    public boolean isEnableOrderBy() { return enableOrderByCheck.isSelected(); }
    public boolean isEnableTimeBlind() { return enableTimeBlindCheck.isSelected(); }
    public boolean isEnableCookieInjection() { return enableCookieInjectionCheck.isSelected(); }

    public Set<String> getExcludedExtensions() {
        Set<String> exts = new HashSet<>();
        String[] parts = excludeExtField.getText().split("\\|");
        for (String part : parts) {
            String ext = part.trim().toLowerCase();
            if (!ext.isEmpty()) exts.add(ext);
        }
        return exts;
    }

    /**
     * 创建控制按钮行（v6.0 — 新增手动去重按钮）
     *
     * @param stateProvider 当前引擎状态的提供者，用于动态更新按钮状态
     */
    public static ButtonBarResult createButtonBar(ActionListener startAction,
                                                  ActionListener pauseAction,
                                                  ActionListener stopAction,
                                                  ActionListener exportAction,
                                                  ActionListener loadProxyAction,
                                                  ActionListener clearQueueAction,
                                                  ActionListener deduplicateAction) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton startBtn = new JButton("▶ 开始探测");
        JButton pauseBtn = new JButton("⏸ 暂停");
        JButton stopBtn = new JButton("■ 停止");

        startBtn.addActionListener(startAction);
        pauseBtn.addActionListener(pauseAction);
        stopBtn.addActionListener(stopAction);
        bar.add(startBtn);
        bar.add(pauseBtn);
        bar.add(stopBtn);

        bar.add(Box.createHorizontalStrut(10));

        // 批量加载按钮（仅保留 Proxy History）
        JButton loadProxyBtn = new JButton("从 Proxy History 加载");
        loadProxyBtn.setToolTipText("将 Proxy 历史记录中所有请求添加到任务列表");
        loadProxyBtn.addActionListener(loadProxyAction);
        bar.add(loadProxyBtn);

        JButton clearQueueBtn = new JButton("清空列表");
        clearQueueBtn.setToolTipText("清空当前任务列表");
        clearQueueBtn.addActionListener(clearQueueAction);
        bar.add(clearQueueBtn);

        // v6.0: 手动去重按钮
        JButton dedupBtn = new JButton("🔍 去重");
        dedupBtn.setToolTipText("手动去重：移除相同 URL 的重复任务，保留第一个");
        dedupBtn.addActionListener(deduplicateAction);
        bar.add(dedupBtn);

        bar.add(Box.createHorizontalStrut(10));

        JButton exportBtn = new JButton("导出 HTML");
        exportBtn.addActionListener(exportAction);
        bar.add(exportBtn);

        return new ButtonBarResult(bar, startBtn, pauseBtn, stopBtn);
    }

    /**
     * 按钮栏返回结果（包含按钮引用，便于动态控制 enabled 状态）
     */
    public static class ButtonBarResult {
        public final JPanel panel;
        public final JButton startBtn;
        public final JButton pauseBtn;
        public final JButton stopBtn;

        ButtonBarResult(JPanel panel, JButton startBtn, JButton pauseBtn, JButton stopBtn) {
            this.panel = panel;
            this.startBtn = startBtn;
            this.pauseBtn = pauseBtn;
            this.stopBtn = stopBtn;
        }

        /**
         * 根据引擎状态更新按钮的 enabled 状态
         */
        public void updateButtonStates(com.example.burp.sqli.core.ProbeEngine.EngineState state) {
            boolean isIdle = (state == com.example.burp.sqli.core.ProbeEngine.EngineState.IDLE);
            boolean isRunning = (state == com.example.burp.sqli.core.ProbeEngine.EngineState.RUNNING);
            boolean isPaused = (state == com.example.burp.sqli.core.ProbeEngine.EngineState.PAUSED);
            boolean isStopped = (state == com.example.burp.sqli.core.ProbeEngine.EngineState.STOPPED);

            startBtn.setEnabled(isIdle || isPaused || isStopped);
            startBtn.setText(isPaused ? "▶ 继续探测" : "▶ 开始探测");

            pauseBtn.setEnabled(isRunning);
            pauseBtn.setText(isPaused ? "⏸ 已暂停" : "⏸ 暂停");

            stopBtn.setEnabled(isRunning || isPaused);
        }
    }
}
