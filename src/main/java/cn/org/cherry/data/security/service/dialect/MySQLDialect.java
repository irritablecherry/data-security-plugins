package cn.org.cherry.data.security.service.dialect;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.service.DatabaseDialect;
import cn.org.cherry.data.security.service.DataSecurityMetadataManager;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * MySQL数据库方言
 */
public class MySQLDialect implements DatabaseDialect {

    @Override
    public boolean tableExists(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = "SELECT COUNT(1) FROM information_schema.TABLES " +
                    "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, tableName);
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean columnExists(JdbcTemplate jdbcTemplate, String tableName, String columnName) {
        try {
            String sql = "SELECT COUNT(1) FROM information_schema.COLUMNS " +
                    "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, tableName, columnName);
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String generateAddColumnSql(String tableName, String columnName,
                                       String columnLabel, String columnType, String comment) {
        return String.format("ALTER TABLE `%s` ADD COLUMN `%s` %s COMMENT '%s'",
                tableName, columnName, columnType, comment);
    }

    @Override
    public String generateModifyColumnSql(String tableName, String columnName,
                                          String columnLabel, String columnType, String comment) {
        return String.format("ALTER TABLE `%s` MODIFY COLUMN `%s` %s COMMENT '%s'",
                tableName, columnName, columnType, comment);
    }

    @Override
    public String getTextType() {
        return "TEXT";
    }

    @Override
    public String getStringType(int length) {
        return length <= 4000 ?
                String.format("VARCHAR(%d)", length) : "TEXT";
    }

    @Override
    public String getBooleanType() {
        return "TINYINT(1)";
    }

    @Override
    public Integer getRecordCount(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = String.format("SELECT COUNT(1) FROM `%s`", tableName);
            return jdbcTemplate.queryForObject(sql, Integer.class);
        } catch (Exception e) {
            return 0;
        }
    }

    @Override
    public String getPaginationSql(String sql, int offset, int limit) {
        return sql + " LIMIT " + offset + ", " + limit;
    }

    @Override
    public String getCurrentTimeFunction() {
        return "NOW()";
    }

    @Override
    public String getCurrentDateFunction() {
        return "CURDATE()";
    }
}
