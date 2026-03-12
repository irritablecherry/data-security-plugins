package cn.org.cherry.data.security.service.dialect;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.service.DatabaseDialect;
import cn.org.cherry.data.security.service.DataSecurityMetadataManager;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * SQLite数据库方言
 */
public class SQLiteDialect implements DatabaseDialect {
    @Override
    public boolean tableExists(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name=?";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, tableName);
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean columnExists(JdbcTemplate jdbcTemplate, String tableName, String columnName) {
        return false;
    }

    @Override
    public String generateAddColumnSql(String tableName, String columnName,
                                       String columnLabel, String columnType, String comment) {
        // SQLite不支持在ADD COLUMN时添加注释
        return String.format("ALTER TABLE \"%s\" ADD COLUMN \"%s\" %s",
                tableName, columnName, columnType);
    }

    @Override
    public String generateModifyColumnSql(String tableName, String columnName, String columnLabel, String columnType, String comment) {
        return "";
    }

    @Override
    public String getTextType() {
        return "TEXT";
    }

    @Override
    public String getStringType(int length) {
        return "TEXT";
    }

    @Override
    public String getBooleanType() {
        return "INTEGER";
    }

    @Override
    public Integer getRecordCount(JdbcTemplate jdbcTemplate, String tableName) {
        return 0;
    }

    @Override
    public String getPaginationSql(String sql, int offset, int limit) {
        return "";
    }

    @Override
    public String getCurrentTimeFunction() {
        return "";
    }

    @Override
    public String getCurrentDateFunction() {
        return "";
    }
}








