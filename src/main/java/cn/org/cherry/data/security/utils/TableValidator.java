package cn.org.cherry.data.security.utils;

import cn.org.cherry.data.security.config.DataSecurityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 表名验证工具类
 * <p>
 * 提供表名验证功能，防止 SQL 注入攻击。
 * 支持白名单验证和格式验证双重机制。
 * </p>
 *
 * @author Cherry
 * @since 1.0.0
 */
@Slf4j
@Component
public class TableValidator {

    /**
     * 表名白名单缓存
     */
    private static final Set<String> TABLE_WHITELIST = ConcurrentHashMap.newKeySet();

    /**
     * 表名格式正则表达式
     * 只允许字母、数字、下划线，且必须以字母或下划线开头
     */
    private static final String TABLE_NAME_PATTERN = "^[a-zA-Z_][a-zA-Z0-9_]{0,63}$";

    /**
     * 保留字列表（SQL 关键字）
     */
    private static final Set<String> SQL_KEYWORDS = new HashSet<>();

    static {
        // 初始化 SQL 关键字黑名单
        String[] keywords = {
                "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
                "TRUNCATE", "EXEC", "EXECUTE", "UNION", "OR", "AND", "WHERE",
                "FROM", "INTO", "VALUES", "SET", "JOIN", "ON", "GROUP", "ORDER",
                "HAVING", "LIMIT", "OFFSET", "BY", "AS", "NULL", "NOT", "IN",
                "BETWEEN", "LIKE", "EXISTS", "CASE", "WHEN", "THEN", "ELSE",
                "END", "TRUE", "FALSE", "ASC", "DESC", "INDEX", "TABLE", "VIEW",
                "DATABASE", "SCHEMA", "GRANT", "REVOKE", "COMMIT", "ROLLBACK",
                "TRANSACTION", "LOCK", "UNLOCK", "DECLARE", "FETCH", "OPEN",
                "CLOSE", "CURSOR", "TRIGGER", "FUNCTION", "PROCEDURE", "RETURN"
        };
        for (String keyword : keywords) {
            SQL_KEYWORDS.add(keyword.toUpperCase());
        }
    }

    @Autowired(required = false)
    private JdbcTemplate jdbcTemplate;

    @Autowired(required = false)
    private DataSecurityProperties properties;

    /**
     * 初始化：加载已知表到白名单
     */
    @PostConstruct
    public void init() {
        loadKnownTables();
    }

    /**
     * 加载已知表到白名单
     */
    private void loadKnownTables() {
        if (jdbcTemplate == null) {
            log.debug("JdbcTemplate 不可用，跳过表白名单加载");
            return;
        }

        try {
            // 从数据库元数据中加载所有表名
            Set<String> tables = getAllDatabaseTables();
            TABLE_WHITELIST.addAll(tables);
            log.info("已加载 {} 个表到白名单", tables.size());
        } catch (Exception e) {
            log.warn("加载表白名单失败，将仅使用格式验证：{}", e.getMessage());
        }
    }

    /**
     * 获取数据库中所有表名
     *
     * @return 表名集合
     */
    private Set<String> getAllDatabaseTables() {
        Set<String> tables = new HashSet<>();
        try {
            // 使用 JDBC 获取所有表名
            java.sql.Connection conn = jdbcTemplate.getDataSource().getConnection();
            java.sql.DatabaseMetaData metaData = conn.getMetaData();
            java.sql.ResultSet rs = metaData.getTables(null, null, "%", new String[]{"TABLE"});

            while (rs.next()) {
                String tableName = rs.getString("TABLE_NAME");
                tables.add(tableName.toUpperCase());
            }

            rs.close();
            conn.close();
        } catch (Exception e) {
            log.warn("获取数据库表名失败：{}", e.getMessage());
        }
        return tables;
    }

    /**
     * 验证表名是否合法
     * <p>
     * 验证规则：
     * 1. 表名不能为空
     * 2. 表名不能是 SQL 关键字
     * 3. 表名必须符合格式要求（字母、数字、下划线，以字母或下划线开头）
     * 4. 表名长度不能超过 64 个字符
     * 5. 如果白名单已加载，表名必须在白名单中
     * </p>
     *
     * @param tableName 表名
     * @return 如果合法返回 true，否则返回 false
     */
    public static boolean isValidTableName(String tableName) {
        // 1. 检查空值
        if (tableName == null || tableName.trim().isEmpty()) {
            return false;
        }

        tableName = tableName.trim();

        // 2. 检查长度
        if (tableName.length() > 64) {
            return false;
        }

        // 3. 检查是否是 SQL 关键字
        if (SQL_KEYWORDS.contains(tableName.toUpperCase())) {
            log.warn("表名是 SQL 关键字，拒绝访问：{}", tableName);
            return false;
        }

        // 4. 检查格式
        if (!tableName.matches(TABLE_NAME_PATTERN)) {
            log.warn("表名格式不合法：{}", tableName);
            return false;
        }

        // 5. 如果白名单已加载，检查是否在白名单中
        if (!TABLE_WHITELIST.isEmpty() && !TABLE_WHITELIST.contains(tableName.toUpperCase())) {
            log.warn("表名不在白名单中：{}", tableName);
            return false;
        }

        return true;
    }

    /**
     * 验证表名（严格模式）
     * <p>
     * 严格模式下，表名必须在白名单中。
     * </p>
     *
     * @param tableName 表名
     * @throws IllegalArgumentException 如果表名不合法
     */
    public static void validateTableNameStrict(String tableName) {
        if (!isValidTableName(tableName)) {
            throw new IllegalArgumentException("非法的表名：" + tableName);
        }
    }

    /**
     * 添加表到白名单
     *
     * @param tableName 表名
     */
    public static void addToWhitelist(String tableName) {
        if (tableName != null && !tableName.trim().isEmpty()) {
            TABLE_WHITELIST.add(tableName.trim().toUpperCase());
        }
    }

    /**
     * 从白名单中移除表
     *
     * @param tableName 表名
     */
    public static void removeFromWhitelist(String tableName) {
        if (tableName != null && !tableName.trim().isEmpty()) {
            TABLE_WHITELIST.remove(tableName.trim().toUpperCase());
        }
    }

    /**
     * 清空白名单
     */
    public static void clearWhitelist() {
        TABLE_WHITELIST.clear();
    }

    /**
     * 获取白名单大小
     *
     * @return 白名单中的表数量
     */
    public static int getWhitelistSize() {
        return TABLE_WHITELIST.size();
    }
}
