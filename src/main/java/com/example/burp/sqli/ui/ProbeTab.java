package com.example.burp.sqli.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.example.burp.sqli.core.ProbeEngine;
import com.example.burp.sqli.core.ProbeResult;
import com.example.burp.sqli.export.HtmlExporter;
import com.example.burp.sqli.util.ResponseComparator;

import javax.swing.*;
import javax.swing.AbstractAction;
import javax.swing.border.Border;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import javax.swing.InputMap;
import javax.swing.KeyStroke;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

/**
 * 主 Tab 面板（v6.1 — 探测详情表格化版）
 *
 * 核心变更（v6.1 相比 v6.0）：
 *   - 探测详情：由 JTree 改为 JTable 表格
 *   - 列定义：Payload / 状态码 / 响应长度 / 相似度 / 响应时间 / 结果概述
 *   - 结果概述：使用简短判断文字（与 CompareDialog 一致）
 *   - 底部信息栏：双列对比布局（当前 Entry vs Baseline）
 */
public class ProbeTab extends JPanel {

    private final MontoyaApi api;
    private final ProbeEngine engine;
    private final TaskTableModel taskTableModel;
    private final ConfigPanel configPanel;

    // 进度
    private final JProgressBar progressBar;
    private final JLabel progressLabel;

    // 筛选控件
    private final JComboBox<String> statusFilterCombo;
    private final JTextField searchField;

    // 共用详情面板（BurpSuite 内置编辑器）
    private final MessageEditorPanel detailPanel;

    // 探测详情表格（v6.1）
    private TaskRow currentTaskRow = null;
    private EntryTableModel entryTableModel;
    private JTable probeTable;
    private JPanel selectorPanel;

    // 表格
    private final JTable taskTable;

    // 当前详情面板显示来源
    private String detailSource = null;
    private final Timer progressTimer;

    // 按钮栏引用（用于动态控制按钮状态）
    private ConfigPanel.ButtonBarResult buttonBarResult;

    // 右键菜单项引用（用于条件启用，v6.0 新增）
    private JMenuItem compareItemRef;
    private JMenuItem reprobeSuspiciousItemRef;

    // 所有探测结果（用于导出）
    private final java.util.List<ProbeResult> allProbeResults = new java.util.ArrayList<>();

    public ProbeTab(MontoyaApi api) {
        this.api = api;
        this.taskTableModel = new TaskTableModel();
        this.engine = new ProbeEngine(api);
        this.configPanel = new ConfigPanel();

        setLayout(new BorderLayout(0, 2));

        // ========== 顶部：配置 + 按钮 + 进度条 ==========
        JPanel topPanel = new JPanel(new BorderLayout(0, 0));
        topPanel.add(configPanel, BorderLayout.NORTH);

        // 按钮栏
        buttonBarResult = ConfigPanel.createButtonBar(
                e -> onStart(),
                e -> onPause(),
                e -> onStop(),
                e -> onExport(),
                e -> onLoadFromProxyHistory(),
                e -> onClearTasks(),
                e -> onDeduplicate()  // v6.0: 手动去重
        );
        topPanel.add(buttonBarResult.panel, BorderLayout.CENTER);

        // 进度条
        JPanel progressPanel = new JPanel(new BorderLayout(8, 0));
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(300, 18));
        progressPanel.add(progressBar, BorderLayout.WEST);
        progressLabel = new JLabel("就绪");
        progressPanel.add(progressLabel, BorderLayout.CENTER);
        topPanel.add(progressPanel, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);

        // ========== 创建详情面板（BurpSuite 内置编辑器）==========
        detailPanel = new MessageEditorPanel(api);

        // ========== 左侧：统一任务表格 + 筛选 ==========
        JPanel tableSection = new JPanel(new BorderLayout(0, 0));
        tableSection.setBorder(BorderFactory.createTitledBorder("任务列表（单击查看详情，双击打开对比弹窗）"));

        // 筛选栏
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        filterBar.add(new JLabel("状态:"));
        statusFilterCombo = new JComboBox<>(new String[]{"全部", "可疑", "安全", "等待", "测试中", "跳过", "错误"});
        statusFilterCombo.addActionListener(e -> applyFilters());
        filterBar.add(statusFilterCombo);

        filterBar.add(new JLabel("搜索:"));
        searchField = new JTextField(25);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
        });
        filterBar.add(searchField);
        tableSection.add(filterBar, BorderLayout.NORTH);

        // 统一任务表格（v5.9：在 createTaskTable() 中设置）
        taskTable = createTaskTable();

        // 表格单击/双击事件
        taskTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 1) {
                    showTaskDetail();
                } else if (e.getClickCount() == 2) {
                    showTaskCompareDialog();
                }
            }
        });

        // 表格右键菜单
        JPopupMenu tablePopup = new JPopupMenu();
        JMenuItem removeItem = new JMenuItem("从列表移除");
        removeItem.setMnemonic(java.awt.event.KeyEvent.VK_DELETE);  // Delete 快捷键提示
        removeItem.addActionListener(e -> removeSelectedTask());
        tablePopup.add(removeItem);
        JMenuItem compareItem = new JMenuItem("查看响应对比");
        compareItem.setMnemonic(java.awt.event.KeyEvent.VK_ENTER);   // Enter 快捷键提示
        compareItem.addActionListener(e -> showTaskCompareDialog());
        tablePopup.add(compareItem);
        JMenuItem repeaterItem = new JMenuItem("发送到 Repeater (R)");
        repeaterItem.addActionListener(e -> sendToRepeater());
        tablePopup.add(repeaterItem);
        tablePopup.addSeparator();
        JMenuItem reprobeOneItem = new JMenuItem("重新探测（使用当前配置）");
        reprobeOneItem.setToolTipText("重置该任务的探测结果，使用当前配置重新探测");
        reprobeOneItem.addActionListener(e -> reprobeSelectedTask());
        tablePopup.add(reprobeOneItem);
        JMenuItem reprobeSuspiciousItem = new JMenuItem("重新探测所有可疑任务");
        reprobeSuspiciousItem.setToolTipText("重置所有可疑任务的结果，使用当前配置重新探测");
        reprobeSuspiciousItem.addActionListener(e -> reprobeAllSuspicious());
        tablePopup.add(reprobeSuspiciousItem);
        taskTable.setComponentPopupMenu(tablePopup);

        // 保存菜单项引用，用于条件启用
        compareItemRef = compareItem;
        reprobeSuspiciousItemRef = reprobeSuspiciousItem;

        // 表格选中变化时更新右键菜单状态
        taskTable.getSelectionModel().addListSelectionListener(e -> {
            updatePopupMenuState();
        });

        // ========== 注册快捷键（v6.0 新增）==========
        registerKeyboardShortcuts();

        JScrollPane tableScroll = new JScrollPane(taskTable);
        tableSection.add(tableScroll, BorderLayout.CENTER);

        // ========== 探测条目选择器面板（JList）==========
        // 探测条目列表在任务列表右侧
        selectorPanel = createSelectorPanel();

        // ========== 主体内容区：上方（任务列表 + 探测条目），下方详情（全宽）==========
        // 上方区域：任务列表（左侧）+ 探测条目列表（右侧）
        JSplitPane topContentSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                tableSection,
                selectorPanel
        );
        topContentSplit.setResizeWeight(0.65);   // 任务列表占 65%，探测条目占 35%
        topContentSplit.setDividerLocation(500); // 初始分割位置
        topContentSplit.setMinimumSize(new Dimension(800, 250));

        // 整体垂直布局：上方内容 + 下方详情面板（全宽）
        JSplitPane mainSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                topContentSplit,
                detailPanel
        );
        mainSplit.setResizeWeight(0.45);   // 上方占 45%，下方详情占 55%
        mainSplit.setDividerLocation(300); // 初始分割位置
        mainSplit.setMinimumSize(new Dimension(800, 400));
        add(mainSplit, BorderLayout.CENTER);

        // ========== 注册引擎监听器 ==========
        engine.setTaskUpdateListener(new ProbeEngine.TaskUpdateListener() {
            @Override
            public void onTasksReset() {
                taskTableModel.setData(engine.getTaskRowsSnapshot());
            }

            @Override
            public void onTaskUpdated(TaskRow row, int allRowIndex) {
                // 只更新被修改的任务行
                if (allRowIndex >= 0) {
                    taskTableModel.fireRowUpdated(allRowIndex);
                } else {
                    taskTableModel.fireAllRowsUpdated();
                }

                // 只更新当前选中任务的探测详情表格
                if (currentTaskRow != null && currentTaskRow == row) {
                    SwingUtilities.invokeLater(() -> updateProbeTable());
                }
            }

            @Override
            public void onResultReceived(TaskRow row, ProbeResult result) {
                // 记录结果（用于导出）
                synchronized (allProbeResults) {
                    allProbeResults.add(result);
                }

                // 只更新当前选中任务的探测详情表格
                if (currentTaskRow != null && currentTaskRow == row) {
                    SwingUtilities.invokeLater(() -> updateProbeTable());
                }
            }

            @Override
            public void onTasksCleared() {
                taskTableModel.clear();
                synchronized (allProbeResults) {
                    allProbeResults.clear();
                }
                detailPanel.clear();
                detailSource = null;
                currentTaskRow = null;
                clearProbeTable();
            }

            @Override
            public void onEngineStateChanged(ProbeEngine.EngineState newState) {
                // 通知按钮栏更新按钮状态
                buttonBarResult.updateButtonStates(newState);
            }
        });

        // 初始按钮状态
        buttonBarResult.updateButtonStates(engine.getState());

        // ========== 进度更新定时器 ==========
        progressTimer = new Timer("ProgressTimer", true);
        progressTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                SwingUtilities.invokeLater(() -> updateProgress());
            }
        }, 500, 500);
    }

    /**
     * 创建带行级颜色高亮的统一任务表格（v5.9）
     */
    private JTable createTaskTable() {
        JTable table = new JTable(taskTableModel) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                c.setFont(getFont());

                int modelRow = convertRowIndexToModel(row);
                TaskRow taskRow = taskTableModel.getRow(modelRow);

                if (isRowSelected(row)) return c;
                if (taskRow == null) { c.setBackground(Color.WHITE); return c; }

                // v5.9 移除所有颜色高亮，统一白色背景+默认文字颜色
                c.setBackground(Color.WHITE);
                if (c instanceof JLabel jLabel) {
                    jLabel.setForeground(Color.BLACK);
                }

                return c;
            }
        };

        // v5.9: 设置表格属性
        table.setRowHeight(22);
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // v5.9: 设置列宽（固定宽度，避免自动调整导致性能问题）
        table.getColumnModel().getColumn(0).setPreferredWidth(35);   // #
        table.getColumnModel().getColumn(1).setPreferredWidth(50);   // Method
        table.getColumnModel().getColumn(2).setPreferredWidth(400);  // URL（最宽）
        table.getColumnModel().getColumn(3).setPreferredWidth(50);   // 参数
        table.getColumnModel().getColumn(4).setPreferredWidth(80);   // 状态
        table.getColumnModel().getColumn(5).setPreferredWidth(180);  // 结果

        // v5.9: 禁用自动调整模式，使用固定比例
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

        return table;
    }

    /**
     * 创建探测详情表格（v6.1）
     * 替代 JTree，按表格形式显示每个检测器的所有 Entry
     */
    private JTable createProbeTable() {
        entryTableModel = new EntryTableModel();
        JTable table = new JTable(entryTableModel) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                c.setFont(getFont());

                // 所有单元格靠左对齐
                if (c instanceof JLabel jLabel) {
                    jLabel.setHorizontalAlignment(SwingConstants.LEFT);
                }

                if (isRowSelected(row)) return c;

                EntryTableModel.EntryRow entryRow = entryTableModel.getRow(row);
                if (entryRow == null) { c.setBackground(Color.WHITE); return c; }

                // Baseline 行加粗
                boolean isBaseline = entryRow.entry == entryRow.baseline;
                if (c instanceof JLabel jLabel) {
                    if (isBaseline) {
                        jLabel.setFont(getFont().deriveFont(Font.BOLD));
                    } else {
                        jLabel.setFont(getFont());
                    }
                }

                return c;
            }
        };

        // 表格属性
        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // 列宽设置
        table.getColumnModel().getColumn(0).setPreferredWidth(200);  // Payload
        table.getColumnModel().getColumn(1).setPreferredWidth(60);   // 状态码
        table.getColumnModel().getColumn(2).setPreferredWidth(80);    // 响应长度
        table.getColumnModel().getColumn(3).setPreferredWidth(60);    // 相似度
        table.getColumnModel().getColumn(4).setPreferredWidth(70);    // 响应时间
        table.getColumnModel().getColumn(5).setPreferredWidth(180);  // 结果概述

        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

        // 所有列靠左对齐
        javax.swing.table.DefaultTableCellRenderer leftRenderer = new javax.swing.table.DefaultTableCellRenderer();
        leftRenderer.setHorizontalAlignment(SwingConstants.LEFT);
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(leftRenderer);
        }

        // 单击选中行，更新详情面板
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 1) {
                    int row = table.getSelectedRow();
                    if (row >= 0) {
                        EntryTableModel.EntryRow entryRow = entryTableModel.getRow(row);
                        if (entryRow != null) {
                            displayEntryDetail(entryRow.entry, entryRow.result);
                        }
                    }
                } else if (e.getClickCount() == 2) {
                    // 双击打开对比弹窗（使用当前任务的完整结果）
                    if (currentTaskRow != null) {
                        showTaskCompareDialog();
                    }
                }
            }
        });

        return table;
    }

    /**
     * 创建探测详情面板（JTable v6.1）
     * 按表格形式显示每个检测器的所有 Entry
     */
    private JPanel createSelectorPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 0));
        panel.setBorder(BorderFactory.createTitledBorder("探测详情（单击查看详情，双击打开对比弹窗）"));
        panel.setBackground(new Color(248, 248, 248));

        // 探测详情表格
        probeTable = createProbeTable();
        JScrollPane tableScroll = new JScrollPane(probeTable);
        tableScroll.setMinimumSize(new Dimension(280, 100));
        panel.add(tableScroll, BorderLayout.CENTER);

        return panel;
    }

    /**
     * 显示 Entry 详情（v5.9）
     */
    private void displayEntryDetail(ProbeResult.ProbeEntry entry, ProbeResult result) {
        if (entry.getRequestResponse() == null || entry.getRequestResponse().request() == null) {
            detailPanel.clear();
            return;
        }

        // 构建标题
        String title = currentTaskRow.getMethod() + " " + currentTaskRow.getShortUrl();
        title += " | " + result.getParamName() + " (" + result.getDetectorType().getLabel() + ")";
        if (entry.getLabel().startsWith("Baseline")) {
            title += " | [Baseline]";
        } else {
            title += " | " + entry.getLabel();
        }

        detailPanel.setRequestResponse(entry.getRequestResponse(), title, false);
    }

    // ========== 表格操作 ==========

    /**
     * 单击任务行 → 更新探测详情表格（v6.1）
     */
    private void showTaskDetail() {
        int row = taskTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = taskTable.convertRowIndexToModel(row);
        TaskRow taskRow = taskTableModel.getRow(modelRow);
        if (taskRow == null) return;

        currentTaskRow = taskRow;
        detailSource = "task";

        // 更新探测详情表格
        updateProbeTable();

        // 根据状态显示详情
        if (taskRow.isFinished() || taskRow.getStatus() == TaskRow.TaskStatus.TESTING) {
            List<ProbeResult> results = taskRow.getResults();
            if (!results.isEmpty() && entryTableModel.getRowCount() > 0) {
                // 默认选中第一行（Baseline）
                probeTable.setRowSelectionInterval(0, 0);
                EntryTableModel.EntryRow firstEntry = entryTableModel.getRow(0);
                if (firstEntry != null) {
                    displayEntryDetail(firstEntry.entry, firstEntry.result);
                }
            } else if (taskRow.getStatus() == TaskRow.TaskStatus.TESTING) {
                showBaseline(taskRow);
            } else {
                showOriginalRequest(taskRow);
            }
        } else {
            showOriginalRequest(taskRow);
        }
    }

    /**
     * 显示原始请求（无探测数据时）
     */
    private void showOriginalRequest(TaskRow taskRow) {
        clearProbeTable();
        String title = taskRow.getMethod() + " " + taskRow.getShortUrl();
        if (taskRow.hasResponse()) {
            HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(taskRow.getRequest(), taskRow.getResponse());
            detailPanel.setRequestResponse(rr, title, true);
        } else {
            detailPanel.setRequestOnly(taskRow.getRequest(), title);
        }
    }

    /**
     * 显示 baseline 请求（测试中状态）
     */
    private void showBaseline(TaskRow taskRow) {
        clearProbeTable();
        String title = taskRow.getMethod() + " " + taskRow.getShortUrl() + " | 正在提取注入点...";
        if (taskRow.hasResponse()) {
            HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(taskRow.getRequest(), taskRow.getResponse());
            detailPanel.setRequestResponse(rr, title, false);
        } else {
            detailPanel.setRequestOnly(taskRow.getRequest(), title);
        }
    }

    /**
     * 更新探测详情表格（v6.1）
     */
    private void updateProbeTable() {
        if (currentTaskRow == null) {
            clearProbeTable();
            return;
        }

        List<ProbeResult> results = currentTaskRow.getResults();
        if (results.isEmpty()) {
            clearProbeTable();
            return;
        }

        entryTableModel.setEntries(results);
    }

    /**
     * 清空探测详情表格（v6.1）
     */
    private void clearProbeTable() {
        entryTableModel.clear();
    }

    /**
     * 双击任务行 → 打开响应对比弹窗（支持所有参数）（v5.9）
     */
    private void showTaskCompareDialog() {
        int row = taskTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = taskTable.convertRowIndexToModel(row);
        TaskRow taskRow = taskTableModel.getRow(modelRow);

        // v5.9: 更友好的空数据提示
        if (taskRow == null) {
            return;  // 不可能发生，但防御性检查
        }

        List<ProbeResult> results = taskRow.getResults();
        if (results == null || results.isEmpty()) {
            // 根据任务状态给出不同的提示
            TaskRow.TaskStatus status = taskRow.getStatus();
            String message;
            if (status == TaskRow.TaskStatus.QUEUED) {
                message = "该任务尚未开始探测，请先点击「开始探测」";
            } else if (status == TaskRow.TaskStatus.EXTRACTING || status == TaskRow.TaskStatus.TESTING) {
                message = "该任务正在探测中，请稍候...";
            } else if (status == TaskRow.TaskStatus.SKIPPED) {
                message = "该任务无注入点（参数为空或全部被过滤）";
            } else {
                message = "该任务无探测数据";
            }
            JOptionPane.showMessageDialog(this, message, "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        Window parent = SwingUtilities.getWindowAncestor(this);
        CompareDialog dialog;
        if (parent instanceof Frame frame) {
            dialog = new CompareDialog(frame, results, api);
        } else if (parent != null) {
            dialog = new CompareDialog(new Frame(), results, api);
        } else {
            dialog = new CompareDialog((Frame) null, results, api);
        }

        dialog.setModal(true);
        dialog.setLocationRelativeTo(parent);
        dialog.setAlwaysOnTop(true);
        dialog.setVisible(true);
    }

    private void removeSelectedTask() {
        int row = taskTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = taskTable.convertRowIndexToModel(row);
        engine.removeTask(modelRow);
        detailPanel.clear();
        detailSource = null;
        currentTaskRow = null;
        clearProbeTable();
    }

    /**
     * 更新右键菜单项的启用状态（v6.0 新增）
     * 根据选中行的任务状态，动态启用/禁用菜单项
     */
    private void updatePopupMenuState() {
        int row = taskTable.getSelectedRow();
        if (row < 0) {
            // 没有选中行时，禁用需要选中行的菜单项
            if (compareItemRef != null) compareItemRef.setEnabled(false);
            return;
        }

        int modelRow = taskTable.convertRowIndexToModel(row);
        TaskRow taskRow = taskTableModel.getRow(modelRow);

        // "查看响应对比"：仅对已完成行可用
        if (compareItemRef != null) {
            boolean canCompare = taskRow != null && taskRow.isFinished();
            compareItemRef.setEnabled(canCompare);
        }

        // "重新探测所有可疑任务"：仅当存在可疑任务时可用
        if (reprobeSuspiciousItemRef != null) {
            long suspiciousCount = taskTableModel.getAllRows().stream()
                    .filter(TaskRow::hasSuspicious)
                    .count();
            reprobeSuspiciousItemRef.setEnabled(suspiciousCount > 0);
        }
    }

    /**
     * 注册快捷键（v6.0 新增）
     * Enter: 查看响应对比
     * Delete: 从列表移除
     * R: 发送到 Repeater
     */
    private void registerKeyboardShortcuts() {
        // 获取输入映射
        InputMap inputMap = taskTable.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap actionMap = taskTable.getActionMap();

        // Enter 键：查看响应对比
        inputMap.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ENTER, 0), "showCompare");
        actionMap.put("showCompare", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                int row = taskTable.getSelectedRow();
                if (row < 0) return;
                int modelRow = taskTable.convertRowIndexToModel(row);
                TaskRow taskRow = taskTableModel.getRow(modelRow);
                // 只有已完成的任务才能查看对比
                if (taskRow != null && taskRow.isFinished()) {
                    showTaskCompareDialog();
                }
            }
        });

        // Delete 键：从列表移除
        inputMap.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_DELETE, 0), "removeTask");
        actionMap.put("removeTask", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                int row = taskTable.getSelectedRow();
                if (row >= 0) {
                    removeSelectedTask();
                }
            }
        });

        // R 键：发送到 Repeater
        inputMap.put(KeyStroke.getKeyStroke('R', 0), "sendRepeater");
        actionMap.put("sendRepeater", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                int row = taskTable.getSelectedRow();
                if (row >= 0) {
                    sendToRepeater();
                }
            }
        });
    }

    /**
     * 重新探测选中的单个任务
     */
    private void reprobeSelectedTask() {
        int row = taskTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = taskTable.convertRowIndexToModel(row);
        TaskRow taskRow = taskTableModel.getRow(modelRow);
        if (taskRow == null) return;

        // 先应用当前配置
        applyConfigToEngine();
        engine.reprobeTask(taskRow);

        // 清空详情面板
        detailPanel.clear();
        detailSource = null;
        currentTaskRow = taskRow;  // 保持选中当前任务
        clearProbeTable();
    }

    /**
     * 重新探测所有可疑任务
     */
    private void reprobeAllSuspicious() {
        List<TaskRow> suspiciousRows = taskTableModel.getAllRows().stream()
                .filter(TaskRow::hasSuspicious)
                .toList();

        if (suspiciousRows.isEmpty()) {
            JOptionPane.showMessageDialog(this, "没有可疑任务可重新探测", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
                String.format("确定要重新探测 %d 个可疑任务吗？\n使用当前配置重新执行检测。", suspiciousRows.size()),
                "重新探测", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        applyConfigToEngine();
        engine.reprobeTasks(suspiciousRows);

        detailPanel.clear();
        detailSource = null;
        currentTaskRow = null;
        clearProbeTable();
    }

    private void sendToRepeater() {
        int row = taskTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = taskTable.convertRowIndexToModel(row);
        TaskRow taskRow = taskTableModel.getRow(modelRow);
        if (taskRow != null) {
            if (detailSource != null && detailPanel.isRequestModified()) {
                api.repeater().sendToRepeater(detailPanel.getCurrentRequest());
            } else {
                api.repeater().sendToRepeater(taskRow.getRequest());
            }
        }
    }

    // ========== 按钮事件 ==========

    /**
     * 将当前 ConfigPanel 的配置应用到引擎
     */
    private void applyConfigToEngine() {
        engine.setConcurrency(configPanel.getConcurrency());
        engine.setTimeoutMs(configPanel.getTimeout() * 1000);
        engine.setDelayMs(configPanel.getDelay());
        engine.setEnableStringBlind(configPanel.isEnableStringBlind());
        engine.setEnableNumeric(configPanel.isEnableNumeric());
        engine.setEnableOrderBy(configPanel.isEnableOrderBy());
        engine.setEnableTimeBlind(configPanel.isEnableTimeBlind());
        engine.setEnableCookieInjection(configPanel.isEnableCookieInjection());
        engine.setOnlyInScope(configPanel.isOnlyInScope());
        engine.setExcludedExtensions(configPanel.getExcludedExtensions());
    }

    private void onStart() {
        // v6.0: 前置检查 - 检查是否有检测器被勾选
        if (!configPanel.isEnableStringBlind() &&
            !configPanel.isEnableNumeric() &&
            !configPanel.isEnableOrderBy() &&
            !configPanel.isEnableTimeBlind()) {
            JOptionPane.showMessageDialog(this,
                    "请至少勾选一个检测器（字符型/数字型/Order型/时间盲注）\n然后再开始探测。",
                    "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // v6.0: 检查是否有待测任务
        if (engine.getTaskCount() == 0) {
            JOptionPane.showMessageDialog(this,
                    "没有待探测的任务。\n请先从 Proxy History 加载或右键发送请求。",
                    "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        applyConfigToEngine();

        ProbeEngine.EngineState st = engine.getState();
        if (st == ProbeEngine.EngineState.PAUSED) {
            engine.resume();
        } else {
            engine.startFromQueue();
        }
    }

    private void onLoadFromProxyHistory() {
        // 先同步最新配置（确保 in-scope、排除扩展名等配置是最新的）
        applyConfigToEngine();
        engine.loadFromProxyHistory();
    }

    private void onClearTasks() {
        engine.clearTasks();
    }

    // v6.0: 手动去重
    private void onDeduplicate() {
        int removed = engine.deduplicate();
        if (removed > 0) {
            JOptionPane.showMessageDialog(this,
                    "去重完成：移除了 " + removed + " 个重复任务",
                    "去重结果",
                    JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                    "没有发现重复任务",
                    "去重结果",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void onPause() {
        ProbeEngine.EngineState st = engine.getState();
        if (st == ProbeEngine.EngineState.RUNNING) {
            engine.pause();
        } else if (st == ProbeEngine.EngineState.PAUSED) {
            engine.resume();
        }
    }

    private void onStop() {
        engine.stop();
    }

    private void onExport() {
        List<ProbeResult> results;
        synchronized (allProbeResults) {
            results = new java.util.ArrayList<>(allProbeResults);
        }
        if (results.isEmpty()) {
            JOptionPane.showMessageDialog(this, "暂无结果可导出", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("sqli-probe-report.html"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                HtmlExporter.export(results, fc.getSelectedFile().getAbsolutePath());
                JOptionPane.showMessageDialog(this, "导出成功: " + fc.getSelectedFile().getAbsolutePath(),
                        "导出", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "导出失败: " + e.getMessage(),
                        "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ========== 进度 ==========

    private void updateProgress() {
        int total = engine.getTotalTasks();
        int completed = engine.getCompletedTasks();
        int suspicious = engine.getSuspiciousCount();
        int safe = engine.getSafeCount();
        int pending = engine.getPendingTasks();
        double pct = engine.getProgressPercent();

        progressBar.setValue((int) pct);

        ProbeEngine.EngineState st = engine.getState();
        if (st == ProbeEngine.EngineState.IDLE) {
            // IDLE 状态：检查是刚完成还是空闲状态
            if (total > 0 && completed >= total) {
                // 所有任务已完成
                int taskCount = engine.getTaskCount();
                progressLabel.setText(String.format("✓ 探测完成！可疑: %d | 安全: %d | 总任务: %d 条  ← 右键可重新探测",
                        suspicious, safe, taskCount));
            } else if (engine.getTaskCount() > 0) {
                // 有任务但还未开始或全部跳过
                progressLabel.setText("就绪 | 任务: " + engine.getTaskCount() + " 条  ← 点击「开始探测」");
            } else {
                progressLabel.setText("就绪  ← 从 Proxy History 加载或右键发送请求");
            }
        } else if (st == ProbeEngine.EngineState.PAUSED) {
            progressLabel.setText(String.format("⏸ 已暂停 | 进度: %d/%d (%.1f%%) | 可疑: %d | 安全: %d | 待检: %d",
                    completed, total, pct, suspicious, safe, pending));
        } else if (st == ProbeEngine.EngineState.STOPPED) {
            progressLabel.setText(String.format("■ 已停止 | 已完成: %d/%d | 可疑: %d | 安全: %d | 待检: %d  ← 点击「开始探测」继续",
                    completed, total, suspicious, safe, pending));
        } else {
            // RUNNING
            progressLabel.setText(String.format("进度: %d/%d (%.1f%%) | 可疑: %d | 安全: %d | 待检: %d",
                    completed, total, pct, suspicious, safe, pending));
        }
    }

    private void applyFilters() {
        String status = (String) statusFilterCombo.getSelectedItem();
        String keyword = searchField.getText();
        taskTableModel.setCombinedFilter(status, null, keyword);
    }

    public void cleanup() {
        progressTimer.cancel();
        engine.cleanup();
    }

    public ProbeEngine getEngine() { return engine; }

    // ========== 工具方法 ==========

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() > maxLen ? s.substring(0, maxLen - 3) + "..." : s;
    }
}
