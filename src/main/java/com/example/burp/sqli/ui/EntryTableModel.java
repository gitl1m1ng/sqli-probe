package com.example.burp.sqli.ui;

import com.example.burp.sqli.core.ProbeResult;
import com.example.burp.sqli.util.ResponseComparator;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 探测详情表格模型（v6.1）
 *
 * 替代 JTree，按表格形式显示每个检测器的所有 Entry。
 * 列定义：Payload | 状态码 | 响应长度 | 相似度 | 响应时间 | 结果概述
 */
public class EntryTableModel extends AbstractTableModel {

    private final List<EntryRow> entries = new ArrayList<>();

    // 6列定义
    private static final String[] COLUMNS = {
            "Payload", "状态码", "响应长度", "相似度", "响应时间", "结果概述"
    };
    private static final Class<?>[] COLUMN_TYPES = {
            String.class, Integer.class, Integer.class, String.class, Long.class, String.class
    };

    /**
     * 表格行数据（对应一个 ProbeEntry + 关联的 ProbeResult）
     */
    public static class EntryRow {
        public final ProbeResult.ProbeEntry entry;
        public final ProbeResult result;           // 所属检测器结果
        public final ProbeResult.ProbeEntry baseline; // 该检测器的 baseline

        public EntryRow(ProbeResult.ProbeEntry entry, ProbeResult result, ProbeResult.ProbeEntry baseline) {
            this.entry = entry;
            this.result = result;
            this.baseline = baseline;
        }

        /** 获取响应体字符串 */
        private String getResponseBody(ProbeResult.ProbeEntry e) {
            if (e == null || e.getRequestResponse() == null || e.getRequestResponse().response() == null) {
                return "";
            }
            return e.getRequestResponse().response().bodyToString();
        }

        /** 获取相似度百分比 */
        public String getSimilarity() {
            if (baseline == null || entry == baseline) {
                return "—";
            }
            double sim = ResponseComparator.similarity(
                    getResponseBody(baseline),
                    getResponseBody(entry)
            );
            return String.format("%.0f%%", sim * 100);
        }

        /** 获取结果概述（简短判断文字） */
        public String getResultSummary() {
            if (entry == baseline) {
                return "Baseline";
            }
            // 使用 ResponseComparator.similarity 的判断逻辑
            double sim = ResponseComparator.similarity(
                    getResponseBody(baseline),
                    getResponseBody(entry)
            );
            // 相似度 > 0.9 认为相同
            boolean isSame = sim > 0.9;
            if (isSame) {
                if (entry.hasDbErrors()) {
                    return "响应相同，但检测到DB错误";
                }
                return "响应与基准相同";
            } else {
                if (entry.hasDbErrors()) {
                    return "响应不同，且检测到DB错误";
                }
                if (baseline != null && entry.getResponseTimeMs() > baseline.getResponseTimeMs() + 4000) {
                    return "响应时间异常";
                }
                return "响应与基准显著不同";
            }
        }
    }

    // --- 数据操作 ---

    public void setEntries(List<ProbeResult> results) {
        entries.clear();
        if (results == null || results.isEmpty()) {
            fireTableDataChanged();
            return;
        }

        // 按检测器顺序展开所有 Entry
        for (ProbeResult r : results) {
            ProbeResult.ProbeEntry baseline = r.getBaseline();
            for (ProbeResult.ProbeEntry e : r.getEntries()) {
                entries.add(new EntryRow(e, r, baseline));
            }
        }
        fireTableDataChanged();
    }

    public void clear() {
        entries.clear();
        fireTableDataChanged();
    }

    public EntryRow getRow(int index) {
        if (index < 0 || index >= entries.size()) return null;
        return entries.get(index);
    }

    public int getRowCount() { return entries.size(); }

    // --- TableModel 接口 ---

    @Override
    public int getColumnCount() { return COLUMNS.length; }

    @Override
    public String getColumnName(int column) { return COLUMNS[column]; }

    @Override
    public Class<?> getColumnClass(int columnIndex) { return COLUMN_TYPES[columnIndex]; }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        EntryRow row = entries.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.entry.getPayload();                    // Payload
            case 1 -> row.entry.getStatusCode();               // 状态码
            case 2 -> row.entry.getResponseLength();            // 响应长度（纯数字）
            case 3 -> row.getSimilarity();                      // 相似度
            case 4 -> row.entry.getResponseTimeMs();            // 响应时间
            case 5 -> row.getResultSummary();                    // 结果概述
            default -> "";
        };
    }
}
