package cn.org.cherry.data.security.service.dialect;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.service.DatabaseDialect;
import cn.org.cherry.data.security.service.DataSecurityMetadataManager;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * 达梦数据库方言
 */
public class DMDialect implements DatabaseDialect {
    @Override
    public boolean tableExists(JdbcTemplate jdbcTemplate, String tableName) {
        return false;
    }

    @Override
    public boolean columnExists(JdbcTemplate jdbcTemplate, String tableName, String columnName) {
        return false;
    }

    @Override
    public String generateAddColumnSql(String tableName, String columnName,
                                       String columnLabel, String columnType, String comment) {
        return String.format("ALTER TABLE \"%s\" ADD \"%s\" %s",
                tableName, columnName, columnType);
    }

    @Override
    public String generateModifyColumnSql(String tableName, String columnName, String columnLabel, String columnType, String comment) {
        return "";
    }

    @Override
    public String getTextType() {
        return "CLOB";
    }

    @Override
    public String getStringType(int length) {
        return "";
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
