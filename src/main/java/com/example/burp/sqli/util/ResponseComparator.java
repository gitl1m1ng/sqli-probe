package com.example.burp.sqli.util;

/**
 * 响应对比工具
 * 计算响应差异，生成差异高亮文本。
 */
public final class ResponseComparator {

    private ResponseComparator() {}

    /**
     * 计算两个响应体的相似度（0.0 ~ 1.0）
     * 基于简单的 Jaccard 系数（n-gram）
     */
    public static double similarity(String a, String b) {
        if (a == null || b == null) return 0;
        if (a.equals(b)) return 1.0;

        int n = 4; // 4-gram
        java.util.Set<String> setA = ngrams(a, n);
        java.util.Set<String> setB = ngrams(b, n);

        if (setA.isEmpty() && setB.isEmpty()) return 1.0;
        if (setA.isEmpty() || setB.isEmpty()) return 0.0;

        int intersection = 0;
        for (String gram : setA) {
            if (setB.contains(gram)) intersection++;
        }

        return (double) intersection / (setA.size() + setB.size() - intersection);
    }

    /**
     * 生成带 HTML 差异高亮的响应文本
     * 与 baseline 不同的部分用 <mark> 标签包裹
     */
    public static String highlightDifferencesHtml(String baseline, String current) {
        if (baseline == null || current == null) return escapeHtml(current != null ? current : "");
        if (baseline.equals(current)) return escapeHtml(current);

        StringBuilder html = new StringBuilder();
        int blen = baseline.length();
        int clen = current.length();
        int maxLen = Math.max(blen, clen);
        int minLen = Math.min(blen, clen);

        // 找到公共前缀
        int prefixEnd = 0;
        while (prefixEnd < minLen && baseline.charAt(prefixEnd) == current.charAt(prefixEnd)) {
            prefixEnd++;
        }

        // 找到公共后缀
        int suffixStart = 0;
        while (suffixStart < minLen - prefixEnd
                && baseline.charAt(blen - 1 - suffixStart) == current.charAt(clen - 1 - suffixStart)) {
            suffixStart++;
        }

        // 前缀（相同）
        if (prefixEnd > 0) {
            html.append(escapeHtml(current.substring(0, prefixEnd)));
        }

        // 中间差异部分（高亮）
        int diffEnd = clen - suffixStart;
        if (diffEnd > prefixEnd) {
            html.append("<mark style=\"background:#fff3cd;padding:0 2px;\">");
            html.append(escapeHtml(current.substring(prefixEnd, diffEnd)));
            html.append("</mark>");
        }

        // 后缀（相同）
        if (suffixStart > 0) {
            html.append(escapeHtml(current.substring(diffEnd)));
        }

        return html.toString();
    }

    private static java.util.Set<String> ngrams(String s, int n) {
        java.util.Set<String> set = new java.util.HashSet<>();
        if (s.length() < n) {
            set.add(s);
            return set;
        }
        for (int i = 0; i <= s.length() - n; i++) {
            set.add(s.substring(i, i + n));
        }
        return set;
    }

    public static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
