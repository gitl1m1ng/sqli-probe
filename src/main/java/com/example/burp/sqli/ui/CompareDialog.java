package com.example.burp.sqli.ui;

import burp.api.montoya.MontoyaApi;
import com.example.burp.sqli.core.ProbeResult;
import com.example.burp.sqli.util.ResponseComparator;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * 响应对比弹窗
 * 双击结果行打开，并排展示所有探测请求的响应对比。
 * 差异内容用黄色高亮标注，DB 错误用红色标注。
 */
public class CompareDialog extends JDialog {

    private final List<ProbeResult> results;
    private final MontoyaApi api;
    private int currentResultIndex = 0;

    /**
     * 构造方法（单参数版本，保持向后兼容）
     */
    public CompareDialog(Frame owner, ProbeResult result, MontoyaApi api) {
        this(owner, List.of(result), api);
    }

    /**
     * 构造方法（多参数版本）
     */
    public CompareDialog(Frame owner, List<ProbeResult> results, MontoyaApi api) {
        super(owner, "响应对比 - " + (results.isEmpty() ? "" : results.get(0).getUrl()), true);
        this.results = results;
        this.api = api;

        // 设置标题
        if (results.size() > 1) {
            setTitle("响应对比 - " + results.get(0).getUrl() + " (" + results.size() + " 个参数)");
        } else if (!results.isEmpty()) {
            setTitle("响应对比 - " + results.get(0).getUrl() + " ? " + results.get(0).getParamName());
        }

        setSize(1100, 750);
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout());

        // 顶部：参数选择栏
        add(buildParamSelector(), BorderLayout.NORTH);

        // 中间对比面板（可滚动）
        JScrollPane scrollPane = new JScrollPane(buildComparePanel());
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        add(scrollPane, BorderLayout.CENTER);

        // 底部按钮
        add(buildButtonBar(), BorderLayout.SOUTH);
    }

    /**
     * 构建参数选择栏（v6.0 — 优化布局，支持换行显示）
     */
    private JComponent buildParamSelector() {
        // 使用垂直 BoxLayout，每行一个参数的所有检测器
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEtchedBorder());

        // 添加标题
        JLabel titleLabel = new JLabel("  参数选择:");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(5));

        ButtonGroup group = new ButtonGroup();
        for (int i = 0; i < results.size(); i++) {
            final int idx = i;
            ProbeResult r = results.get(i);

            // 每个参数一行水平面板
            JPanel paramRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
            paramRow.setAlignmentX(Component.LEFT_ALIGNMENT);

            // 参数名称标签
            JLabel paramLabel = new JLabel(r.getParamName() + ":");
            paramLabel.setFont(paramLabel.getFont().deriveFont(Font.BOLD));
            paramRow.add(paramLabel);

            // 检测器类型按钮（使用紧凑标签）
            JToggleButton btn = new JToggleButton(getCompactDetectorLabel(r.getDetectorType()));
            btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 11));
            btn.addActionListener(e -> {
                currentResultIndex = idx;
                updateComparePanel();
            });
            group.add(btn);
            paramRow.add(btn);

            // 高亮可疑参数
            if (r.getStatus() == ProbeResult.Status.SUSPICIOUS) {
                btn.setForeground(Color.RED);
                btn.setFont(btn.getFont().deriveFont(Font.BOLD));
                btn.setBorder(BorderFactory.createLineBorder(Color.RED, 2));
            }

            // 显示状态
            String statusText = r.getStatus() == ProbeResult.Status.SUSPICIOUS ? "⚠ 可疑" : "✓ 安全";
            JLabel statusLabel = new JLabel(statusText);
            statusLabel.setForeground(r.getStatus() == ProbeResult.Status.SUSPICIOUS ? Color.RED : new Color(0, 128, 0));
            statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11));
            paramRow.add(statusLabel);

            // 默认选中第一个
            if (i == 0) btn.setSelected(true);

            panel.add(paramRow);
        }

        // 如果参数太多，使用滚动
        if (results.size() > 6) {
            JScrollPane scrollPane = new JScrollPane(panel);
            scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
            scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            scrollPane.setPreferredSize(new Dimension(300, 200));
            return scrollPane;
        }

        return panel;
    }

    /**
     * 获取紧凑的检测器标签（v6.0）
     */
    private String getCompactDetectorLabel(ProbeResult.DetectorType type) {
        return switch (type) {
            case STRING_BLIND -> "[字] 字符型";
            case NUMERIC -> "[数] 数字型";
            case ORDER_BY -> "[序] Order型";
            case TIME_BLIND -> "[时] 时间盲注";
            default -> type.getLabel();
        };
    }

    /**
     * 更新对比面板（切换参数时调用）
     */
    private void updateComparePanel() {
        // 移除旧面板，添加新面板
        Component center = ((BorderLayout) getContentPane().getLayout()).getLayoutComponent(BorderLayout.CENTER);
        if (center != null) {
            remove(center);
        }
        JScrollPane scrollPane = new JScrollPane(buildComparePanel());
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        add(scrollPane, BorderLayout.CENTER);
        revalidate();
        repaint();
    }

    /**
     * 获取当前选中的结果
     */
    private ProbeResult getCurrentResult() {
        if (results.isEmpty() || currentResultIndex < 0 || currentResultIndex >= results.size()) {
            return null;
        }
        return results.get(currentResultIndex);
    }

    private JPanel buildSummary() {
        ProbeResult result = getCurrentResult();
        if (result == null) {
            JPanel panel = new JPanel();
            panel.add(new JLabel("无探测数据"));
            return panel;
        }

        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        panel.setBorder(BorderFactory.createEtchedBorder());

        panel.add(new JLabel("参数: " + result.getParamName()));
        panel.add(new JLabel("类型: " + result.getDetectorType().getLabel()));

        String statusText = result.getStatus() == ProbeResult.Status.SUSPICIOUS
                ? "\u26A0 可疑" : "\u2713 安全";
        JLabel statusLabel = new JLabel("状态: " + statusText);
        statusLabel.setForeground(result.getStatus() == ProbeResult.Status.SUSPICIOUS
                ? Color.RED : new Color(0, 128, 0));
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        panel.add(statusLabel);

        panel.add(new JLabel(String.format("最大长度差: %.1f%%", result.getMaxLengthDiffPercent())));
        panel.add(new JLabel("总耗时: " + formatTime(result.getTotalTimeMs())));

        return panel;
    }

    private JPanel buildComparePanel() {
        ProbeResult result = getCurrentResult();
        if (result == null) {
            JPanel panel = new JPanel();
            panel.add(new JLabel("无探测数据"));
            return panel;
        }

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        ProbeResult.ProbeEntry baseline = result.getBaseline();
        int baselineLength = baseline != null ? baseline.getResponseLength() : 0;

        for (int i = 0; i < result.getEntries().size(); i++) {
            ProbeResult.ProbeEntry entry = result.getEntries().get(i);

            JPanel entryPanel = new JPanel(new BorderLayout(2, 2));
            entryPanel.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(Color.LIGHT_GRAY),
                    BorderFactory.createEmptyBorder(4, 4, 4, 4)
            ));

            // 左侧：请求信息
            JPanel leftPanel = new JPanel();
            leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
            leftPanel.setPreferredSize(new Dimension(280, 0));
            leftPanel.setMinimumSize(new Dimension(280, 0));

            JLabel labelLabel = new JLabel("  " + entry.getLabel());
            labelLabel.setFont(labelLabel.getFont().deriveFont(Font.BOLD));
            leftPanel.add(labelLabel);

            JLabel payloadLabel = new JLabel("  Payload: " + truncate(entry.getPayload(), 40));
            leftPanel.add(payloadLabel);

            String respInfo = String.format("  状态: %d | 长度: %d | 耗时: %dms",
                    entry.getStatusCode(), entry.getResponseLength(), entry.getResponseTimeMs());
            leftPanel.add(new JLabel(respInfo));

            // 差异信息（v4.9 移除长度差颜色高亮）
            double diffPct = entry.getLengthDiffPercent(baselineLength);
            String diffText;
            if (i == 0) {
                diffText = "  (baseline)";
            } else {
                diffText = String.format("  长度差异: %s%.1f%%",
                        diffPct > 0 ? "+" : "", diffPct);
            }
            JLabel diffLabel = new JLabel(diffText);
            leftPanel.add(diffLabel);

            // DB 错误标记
            if (entry.hasDbErrors()) {
                JLabel dbErrorLabel = new JLabel("  \uD83D\uDD34 DB错误: " + String.join(", ", entry.getDbErrors()));
                dbErrorLabel.setForeground(Color.RED);
                leftPanel.add(dbErrorLabel);
            }

            // 与 baseline 的相似度标注（v5.5：按注入类型显示不同判断文字）
            if (i > 0 && baseline != null) {
                String baselineBody = baseline.getRequestResponse() != null && baseline.getRequestResponse().response() != null
                        ? baseline.getRequestResponse().response().bodyToString() : "";
                String currentBody = entry.getRequestResponse() != null && entry.getRequestResponse().response() != null
                        ? entry.getRequestResponse().response().bodyToString() : "";
                int baselineStatus = baseline.getStatusCode();
                int currentStatus = entry.getStatusCode();
                double sim = ResponseComparator.similarity(baselineBody, currentBody);
                boolean statusDiff = baselineStatus != currentStatus;
                boolean responseSame = sim > 0.95 && !statusDiff;
                boolean responseDiff = sim < 0.95 || statusDiff;

                String label = entry.getLabel();
                ProbeResult.DetectorType detectorType = result.getDetectorType();

                if (detectorType == ProbeResult.DetectorType.STRING_BLIND) {
                    // ===== 字符型布尔盲注（v5.7） =====
                    // 单引号 ' 仅作为布尔盲注辅助判断，不单独标红
                    boolean isPoc1 = label != null && label.startsWith("poc1:");
                    boolean isPoc2_3_4 = !isPoc1 && label != null && (
                            label.startsWith("poc2:") || label.startsWith("poc3:") || label.startsWith("poc4:"));

                    if (isPoc1) {
                        // poc1 响应不同不标红，只是布尔盲注判断的一部分
                        if (responseDiff) {
                            addLabel(leftPanel, "  单引号触发响应变化", Color.BLACK);
                        } else {
                            addLabel(leftPanel, "  与原始响应相同", Color.GRAY);
                        }
                    } else if (isPoc2_3_4) {
                        // 获取 poc1 与 baseline 的相似度和状态码（v5.8.2：统一判断逻辑）
                        double poc1Sim = 1.0;
                        boolean poc1Exists = false;
                        boolean poc1DiffFromBaseline = false;  // poc1 与 baseline 是否不同
                        int poc1Status = -1;
                        for (ProbeResult.ProbeEntry pe : result.getEntries()) {
                            if (pe.getLabel() != null && pe.getLabel().startsWith("poc1:")) {
                                poc1Exists = true;
                                if (pe.getRequestResponse() != null && pe.getRequestResponse().response() != null) {
                                    String poc1Body = pe.getRequestResponse().response().bodyToString();
                                    poc1Sim = ResponseComparator.similarity(baselineBody, poc1Body);
                                    poc1Status = pe.getStatusCode();
                                    // 统一判断：相似度<0.95 或 状态码不同 → 不同（与 StringBlindDetector 一致）
                                    poc1DiffFromBaseline = poc1Sim < 0.95 || poc1Status != baselineStatus;
                                }
                                break;
                            }
                        }
                        // 只有当 poc1 存在且 poc1 与 baseline 不同时，才显示注入存在
                        // 统一判断逻辑：与 StringBlindDetector 一致
                        if (responseSame && poc1Exists && poc1DiffFromBaseline) {
                            addLabel(leftPanel, "  ! 与原始响应相同 - 闭合成功，注入存在！", Color.RED);
                        } else if (responseSame && poc1Exists && !poc1DiffFromBaseline) {
                            addLabel(leftPanel, "  - 与原始响应相同（poc1无变化，不能判断为注入）", Color.GRAY);
                        } else if (responseSame) {
                            addLabel(leftPanel, "  - 与原始响应相同（无法获取poc1对比）", Color.GRAY);
                        } else {
                            addLabel(leftPanel, "  - 与原始响应不同 - 闭合失败", Color.GRAY);
                        }
                    } else {
                        if (responseSame) {
                            addLabel(leftPanel, "  - 与原始响应相同", Color.GRAY);
                        } else {
                            addLabel(leftPanel, "  - 与原始响应不同", Color.GRAY);
                        }
                    }

                } else if (detectorType == ProbeResult.DetectorType.NUMERIC) {
                    // ===== 数字型注入 =====
                    boolean isPoc1 = label != null && label.startsWith("poc1:");
                    boolean isPoc2 = label != null && label.startsWith("poc2:");

                    if (isPoc1) {
                        // *1 payload
                        if (responseSame) {
                            addLabel(leftPanel, "  - 与原始响应相同 - SQL引擎计算参数，*1恒等", Color.GRAY);
                        } else {
                            addLabel(leftPanel, "  ! 与原始响应不同 - 参数未被SQL计算", Color.RED);
                        }
                    } else if (isPoc2) {
                        // *0 payload
                        if (responseDiff) {
                            addLabel(leftPanel, "  ! 与原始响应不同 - SQL引擎计算，*0结果归零", Color.RED);
                        } else {
                            addLabel(leftPanel, "  - 与原始响应相同 - 参数未参与SQL计算", Color.GRAY);
                        }
                    } else {
                        if (responseSame) {
                            addLabel(leftPanel, "  - 与原始响应相同", Color.GRAY);
                        } else {
                            addLabel(leftPanel, "  - 与原始响应不同", Color.GRAY);
                        }
                    }

                } else if (detectorType == ProbeResult.DetectorType.TIME_BLIND) {
                    // ===== 时间盲注 =====
                    long baselineTime = baseline.getResponseTimeMs();
                    long currentTime = entry.getResponseTimeMs();
                    long diffTime = currentTime - baselineTime;

                    // v5.8.6: 检查是否为超时标记
                    boolean isTimeout = entry.getLabel() != null && entry.getLabel().contains("TIMEOUT");

                    if (isTimeout) {
                        addLabel(leftPanel, "  ! 请求超时 - SLEEP函数可能执行，注入存在！", Color.RED);
                    } else if (diffTime > 4000) {
                        addLabel(leftPanel, String.format("  ! 响应延迟 %dms - SLEEP函数执行，注入存在！", diffTime), Color.RED);
                    } else {
                        addLabel(leftPanel, String.format("  - 响应正常（延迟 %dms）", diffTime), Color.GRAY);
                    }

                } else if (detectorType == ProbeResult.DetectorType.ORDER_BY) {
                    // ===== Order By 注入（v5.8.4：与 Detector 逻辑一致） =====
                    // 判定逻辑：poc1与baseline相同 且 poc2与baseline不同 → 可疑
                    // poc1: ,1（ASC 升序追加，通常响应相同）
                    // poc2: ,999999（超大分页，会导致响应不同）
                    boolean isPoc1 = label != null && label.startsWith("poc1:");
                    boolean isPoc2 = label != null && label.startsWith("poc2:");

                    if (isPoc1) {
                        // poc1: ,1 追加排序
                        if (responseSame) {
                            addLabel(leftPanel, "  - 与原始响应相同 - ASC升序追加", Color.GRAY);
                        } else {
                            addLabel(leftPanel, "  - 与原始响应不同 - 追加排序导致响应变化", Color.GRAY);
                        }
                    } else if (isPoc2) {
                        // poc2: ,999999 超大分页
                        if (responseDiff) {
                            addLabel(leftPanel, "  ! 与原始响应不同 - 超大分页差异，可能存在注入", Color.RED);
                        } else {
                            addLabel(leftPanel, "  - 与原始响应相同 - 未触发注入", Color.GRAY);
                        }
                    } else {
                        // baseline 或其他
                        if (responseSame) {
                            addLabel(leftPanel, "  - 与原始响应相同", Color.GRAY);
                        } else {
                            addLabel(leftPanel, "  - 与原始响应不同", Color.GRAY);
                        }
                    }

                } else {
                    // 其他类型
                    if (responseSame) {
                        addLabel(leftPanel, "  - 与原始响应相同", Color.GRAY);
                    } else {
                        addLabel(leftPanel, "  - 与原始响应不同", Color.GRAY);
                    }
                }
            }

            entryPanel.add(leftPanel, BorderLayout.WEST);

            // 右侧：响应内容（带差异高亮）
            String responseBody = "";
            if (entry.getRequestResponse() != null && entry.getRequestResponse().response() != null) {
                responseBody = entry.getRequestResponse().response().bodyToString();
            }

            String displayText;
            if (i == 0) {
                displayText = ResponseComparator.escapeHtml(responseBody);
            } else {
                String baselineBody = "";
                if (baseline != null && baseline.getRequestResponse() != null && baseline.getRequestResponse().response() != null) {
                    baselineBody = baseline.getRequestResponse().response().bodyToString();
                }
                displayText = ResponseComparator.highlightDifferencesHtml(baselineBody, responseBody);
            }

            // 限制显示长度，避免超大响应卡顿
            if (displayText.length() > 20000) {
                displayText = displayText.substring(0, 20000) + "\n... (truncated, total " + responseBody.length() + " chars)";
            }

            JEditorPane respPane = new JEditorPane();
            respPane.setContentType("text/html");
            respPane.setText("<pre style='font-family:monospace;font-size:11px;margin:4px;'>" + displayText + "</pre>");
            respPane.setEditable(false);
            respPane.setCaretPosition(0);

            JScrollPane respScroll = new JScrollPane(respPane);
            respScroll.setPreferredSize(new Dimension(600, 120));

            entryPanel.add(respScroll, BorderLayout.CENTER);

            panel.add(entryPanel);
            panel.add(Box.createVerticalStrut(2));
        }

        return panel;
    }

    private JPanel buildButtonBar() {
        ProbeResult result = getCurrentResult();
        if (result == null) {
            return new JPanel();
        }

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        // 发送到 Repeater
        JButton sendToRepeaterBtn = new JButton("发送到 Repeater");
        sendToRepeaterBtn.addActionListener(e -> sendToRepeater(result));
        bar.add(sendToRepeaterBtn);

        // 标记按钮
        JButton markSuspiciousBtn = new JButton("标记: 可疑");
        markSuspiciousBtn.addActionListener(e -> {
            result.setUserMarked(true);
            JOptionPane.showMessageDialog(this, "已标记为可疑", "标记", JOptionPane.INFORMATION_MESSAGE);
        });
        bar.add(markSuspiciousBtn);

        JButton markSafeBtn = new JButton("标记: 安全");
        markSafeBtn.addActionListener(e -> {
            result.setUserMarked(false);
            JOptionPane.showMessageDialog(this, "已标记为安全", "标记", JOptionPane.INFORMATION_MESSAGE);
        });
        bar.add(markSafeBtn);

        // 复制请求
        JButton copyReqBtn = new JButton("复制请求");
        copyReqBtn.addActionListener(e -> copyRequest(result));
        bar.add(copyReqBtn);

        return bar;
    }

    private void sendToRepeater(ProbeResult result) {
        if (api == null || result == null) return;
        // 发送 baseline 请求到 Repeater
        ProbeResult.ProbeEntry baseline = result.getBaseline();
        if (baseline != null && baseline.getRequestResponse() != null) {
            api.repeater().sendToRepeater(baseline.getRequestResponse().request());
        }
    }

    private void copyRequest(ProbeResult result) {
        if (result == null) return;
        ProbeResult.ProbeEntry baseline = result.getBaseline();
        if (baseline != null && baseline.getRequestResponse() != null) {
            String reqStr = baseline.getRequestResponse().request().toString();
            java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(reqStr);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() > maxLen ? s.substring(0, maxLen - 3) + "..." : s;
    }

    private static String formatTime(long ms) {
        if (ms < 1000) return ms + "ms";
        return String.format("%.1fs", ms / 1000.0);
    }

    /**
     * 添加带颜色的标签到面板（v5.5 辅助方法）
     */
    private static void addLabel(JPanel panel, String text, Color color) {
        JLabel label = new JLabel(text);
        label.setForeground(color);
        panel.add(label);
    }
}
