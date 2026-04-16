package com.example.burp.sqli.fingerprint;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 数据库错误特征指纹识别
 * 被动检查响应中是否包含数据库错误信息。
 */
public final class DbErrorFingerprint {

    private DbErrorFingerprint() {}

    private static final List<DbPattern> DB_PATTERNS = List.of(
        // MySQL
        new DbPattern("MySQL", Pattern.compile("you have an error in your sql syntax", Pattern.CASE_INSENSITIVE)),
        new DbPattern("MySQL", Pattern.compile("warning:\\s*mysql_", Pattern.CASE_INSENSITIVE)),
        new DbPattern("MySQL", Pattern.compile("supplied argument is not a valid mysql", Pattern.CASE_INSENSITIVE)),
        new DbPattern("MySQL", Pattern.compile("mysql_fetch_array\\(\\)", Pattern.CASE_INSENSITIVE)),
        new DbPattern("MySQL", Pattern.compile("XPATH syntax error", Pattern.CASE_INSENSITIVE)),
        // PostgreSQL
        new DbPattern("PostgreSQL", Pattern.compile("PostgreSQL.*ERROR", Pattern.CASE_INSENSITIVE)),
        new DbPattern("PostgreSQL", Pattern.compile("ERROR:\\s*syntax error at or near", Pattern.CASE_INSENSITIVE)),
        new DbPattern("PostgreSQL", Pattern.compile("pg_query\\(\\)", Pattern.CASE_INSENSITIVE)),
        new DbPattern("PostgreSQL", Pattern.compile("unterminated quoted string", Pattern.CASE_INSENSITIVE)),
        // MSSQL
        new DbPattern("MSSQL", Pattern.compile("\\[SQL Server\\]", Pattern.CASE_INSENSITIVE)),
        new DbPattern("MSSQL", Pattern.compile("Incorrect syntax near", Pattern.CASE_INSENSITIVE)),
        new DbPattern("MSSQL", Pattern.compile("Unclosed quotation mark", Pattern.CASE_INSENSITIVE)),
        new DbPattern("MSSQL", Pattern.compile("Conversion failed when converting", Pattern.CASE_INSENSITIVE)),
        // Oracle
        new DbPattern("Oracle", Pattern.compile("ORA-[0-9]{4,5}:", Pattern.CASE_INSENSITIVE)),
        new DbPattern("Oracle", Pattern.compile("Oracle error", Pattern.CASE_INSENSITIVE)),
        new DbPattern("Oracle", Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE)),
        // SQLite
        new DbPattern("SQLite", Pattern.compile("SQLite\\.Exception", Pattern.CASE_INSENSITIVE)),
        new DbPattern("SQLite", Pattern.compile("near \".*\": syntax error", Pattern.CASE_INSENSITIVE)),
        // DB2
        new DbPattern("DB2", Pattern.compile("CLI Driver.*DB2", Pattern.CASE_INSENSITIVE)),
        new DbPattern("DB2", Pattern.compile("DB2 SQL error", Pattern.CASE_INSENSITIVE)),
        new DbPattern("DB2", Pattern.compile("SQLCODE=[-\\d]+", Pattern.CASE_INSENSITIVE))
    );

    /**
     * 检测响应中包含的数据库错误信息
     *
     * @param response 完整响应字符串
     * @return 匹配到的数据库类型列表（如 ["MySQL", "PostgreSQL"]）
     */
    public static List<String> detect(String response) {
        List<String> found = new ArrayList<>();
        if (response == null) return found;

        for (DbPattern dp : DB_PATTERNS) {
            if (dp.pattern.matcher(response).find()) {
                if (!found.contains(dp.dbType)) {
                    found.add(dp.dbType);
                }
            }
        }
        return found;
    }

    /**
     * 获取匹配到的所有错误描述（含正则 pattern，用于日志）
     */
    public static List<String> detectWithDetails(String response) {
        List<String> found = new ArrayList<>();
        if (response == null) return found;

        for (DbPattern dp : DB_PATTERNS) {
            if (dp.pattern.matcher(response).find()) {
                found.add(dp.dbType + ": " + dp.pattern.pattern());
            }
        }
        return found;
    }

    private record DbPattern(String dbType, Pattern pattern) {}
}
