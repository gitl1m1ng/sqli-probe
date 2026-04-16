package com.example.burp.sqli.ui;

import com.example.burp.sqli.core.ProbeResult;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * 统一任务表格模型（v5.9）
 *
 * 替代原来的 QueueTableModel + ResultTableModel，
 * 每行对应一个 URL（TaskRow），从入队到完成始终在同一行。
 *
 * 列定义（v5.9 精简版）：# | Method | URL | 参数 | 状态 | 结果
 */
public class TaskTableModel extends AbstractTableModel {

    private final List<TaskRow> allRows = new ArrayList<>();
    private final List<TaskRow> filteredRows = new ArrayList<>();
    private Predicate<TaskRow> filter = r -> true;

    // v5.9: 精简到 6 列，减少视觉负担
    private static final String[] COLUMNS = {
        "#", "Method", "URL", "参数", "状态", "结果"
    };
    private static final Class<?>[] COLUMN_TYPES = {
        Integer.class, String.class, String.class, String.class, String.class, String.class
    };

    // --- 数据操作 ---

    public void addRow(TaskRow row) {
        allRows.add(row);
        applyFilter();
    }

    public void addRows(List<TaskRow> rows) {
        if (rows != null) {
            allRows.addAll(rows);
            applyFilter();
        }
    }

    /**
     * 用完整快照替换数据（保留已有的 results 等状态）
     */
    public void setData(List<TaskRow> newData) {
        allRows.clear();
        if (newData != null) {
            allRows.addAll(newData);
        }
        applyFilter();
    }

    public void removeRow(int index) {
        if (index >= 0 && index < allRows.size()) {
            allRows.remove(index);
            applyFilter();
        }
    }

    public void clear() {
        allRows.clear();
        filteredRows.clear();
        fireTableDataChanged();
    }

    public TaskRow getRow(int index) {
        if (index < 0 || index >= filteredRows.size()) return null;
        return filteredRows.get(index);
    }

    public List<TaskRow> getAllRows() {
        return new ArrayList<>(allRows);
    }

    public int indexOf(TaskRow row) {
        return allRows.indexOf(row);
    }

    // --- 筛选 ---

    public void setFilter(Predicate<TaskRow> filter) {
        this.filter = filter != null ? filter : r -> true;
        applyFilter();
    }

    public void setCombinedFilter(String statusFilter, String typeFilter, String keyword) {
        setFilter(r -> {
            // 状态
            if ("可疑".equals(statusFilter) && !r.hasSuspicious()) return false;
            if ("安全".equals(statusFilter) && (r.hasSuspicious() || !r.isFinished())) return false;
            if ("跳过".equals(statusFilter) && r.getStatus() != TaskRow.TaskStatus.SKIPPED) return false;
            if ("错误".equals(statusFilter) && r.getStatus() != TaskRow.TaskStatus.ERROR) return false;
            // 类型
            if (typeFilter != null && !"全部".equals(typeFilter)) {
                TaskRow.TaskStatus s = r.getOverallStatus();
                if ("测试中".equals(typeFilter) && s != TaskRow.TaskStatus.TESTING
                        && s != TaskRow.TaskStatus.EXTRACTING) return false;
                if ("等待".equals(typeFilter) && s != TaskRow.TaskStatus.QUEUED) return false;
            }
            // 关键词
            if (keyword != null && !keyword.trim().isEmpty()) {
                String kw = keyword.trim().toLowerCase();
                if (!r.getUrl().toLowerCase().contains(kw)) return false;
            }
            return true;
        });
    }

    private void applyFilter() {
        filteredRows.clear();
        for (TaskRow r : allRows) {
            if (filter.test(r)) {
                filteredRows.add(r);
            }
        }
        fireTableDataChanged();
    }

    /**
     * 通知某行已变更（不重建整个表，只刷新特定行）
     */
    public void fireRowUpdated(int allRowIndex) {
        int filteredIndex = filteredRows.indexOf(allRows.get(allRowIndex));
        if (filteredIndex >= 0) {
            fireTableRowsUpdated(filteredIndex, filteredIndex);
        }
    }

    /**
     * 通知所有行可能变更
     */
    public void fireAllRowsUpdated() {
        fireTableDataChanged();
    }

    // --- TableModel 接口 ---

    @Override
    public int getRowCount() { return filteredRows.size(); }

    @Override
    public int getColumnCount() { return COLUMNS.length; }

    @Override
    public String getColumnName(int column) { return COLUMNS[column]; }

    @Override
    public Class<?> getColumnClass(int columnIndex) { return COLUMN_TYPES[columnIndex]; }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TaskRow row = filteredRows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> rowIndex + 1;                        // #
            case 1 -> row.getMethod();                     // Method
            case 2 -> row.getShortUrl();                   // URL
            case 3 -> formatParamCount(row);               // 参数数
            case 4 -> statusLabel(row.getOverallStatus()); // 状态
            case 5 -> formatResult(row);                   // 结果（合并类型+摘要）
            default -> "";
        };
    }

    /**
     * v5.9: 格式化参数数列
     */
    private static String formatParamCount(TaskRow row) {
        int count = row.getInjectionPointCount();
        if (count < 0) return "-";
        if (count == 0) return "无";
        return String.valueOf(count);
    }

    /**
     * v5.9: 格式化结果列（合并类型和状态）
     */
    private static String formatResult(TaskRow row) {
        List<ProbeResult> results = row.getResults();
        if (results.isEmpty()) {
            TaskRow.TaskStatus status = row.getStatus();
            if (status == TaskRow.TaskStatus.QUEUED) return "待检测";
            if (status == TaskRow.TaskStatus.EXTRACTING) return "提取中...";
            if (status == TaskRow.TaskStatus.TESTING) return "检测中: " + row.getCurrentTestInfo();
            if (status == TaskRow.TaskStatus.SKIPPED) return "跳过";
            if (status == TaskRow.TaskStatus.ERROR) return "错误";
            return "";
        }

        // 统计各检测器类型
        java.util.Set<String> types = new java.util.LinkedHashSet<>();
        int suspicious = 0;
        int safe = 0;

        for (ProbeResult r : results) {
            if (r.getStatus() != ProbeResult.Status.PENDING) {
                types.add(r.getDetectorType().getLabel());
            }
            if (r.getStatus() == ProbeResult.Status.SUSPICIOUS) suspicious++;
            else if (r.getStatus() == ProbeResult.Status.SAFE) safe++;
        }

        // 缩写检测器类型
        StringBuilder typeStr = new StringBuilder();
        for (String type : types) {
            if (typeStr.length() > 0) typeStr.append("+");
            typeStr.append(switch (type) {
                case "字符型盲注" -> "字";
                case "数字型" -> "数";
                case "Order型" -> "序";
                case "时间盲注" -> "时";
                default -> type.substring(0, 1);
            });
        }

        // 结果状态
        if (suspicious > 0) {
            return "⚠ " + typeStr + " (" + suspicious + "/" + results.size() + ")";
        }
        return "✓ " + typeStr + " (" + safe + "/" + results.size() + ")";
    }

    private static String detectorLabel(TaskRow row) {
        List<ProbeResult> results = row.getResults();
        if (results.isEmpty()) {
            return "";
        }

        // 收集所有非 PENDING 状态的检测器类型（去重）
        java.util.Set<String> types = new java.util.LinkedHashSet<>();
        for (ProbeResult r : results) {
            if (r.getStatus() != ProbeResult.Status.PENDING) {
                types.add(r.getDetectorType().getLabel());
            }
        }

        if (types.isEmpty()) {
            return "";
        }

        // 如果只有一个类型，直接返回
        if (types.size() == 1) {
            return types.iterator().next();
        }

        // 多个类型时显示缩写（便于表格显示）
        // 字符型→字, 数字型→数, Order型→序, 时间盲注→时
        StringBuilder sb = new StringBuilder();
        for (String type : types) {
            String abbrev = switch (type) {
                case "字符型盲注" -> "字";
                case "数字型" -> "数";
                case "Order型" -> "序";
                case "时间盲注" -> "时";
                default -> type.substring(0, Math.min(1, type.length()));
            };
            if (sb.length() > 0) sb.append("+");
            sb.append(abbrev);
        }
        return sb.toString();
    }

    private static String statusLabel(TaskRow.TaskStatus status) {
        if (status == null) return "";
        return switch (status) {
            case QUEUED -> "\u23F3 等待";
            case EXTRACTING -> "\uD83D\uDD0D 提取注入点";
            case TESTING -> "\uD83D\uDD35 测试中";
            case SUSPICIOUS -> "\u26A0 可疑";
            case SAFE -> "\u2713 安全";
            case SKIPPED -> "\u26AA 跳过";
            case ERROR -> "\u2717 错误";
        };
    }
}
