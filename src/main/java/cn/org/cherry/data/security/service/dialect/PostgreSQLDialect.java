package cn.org.cherry.data.security.service.dialect;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.service.DatabaseDialect;
import cn.org.cherry.data.security.service.DataSecurityMetadataManager;
import org.springframework.jdbc.core.JdbcTemplate;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;

/**
 * PostgreSQL数据库方言
 */
public class PostgreSQLDialect implements DatabaseDialect {

    @Override
    public boolean tableExists(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = "SELECT COUNT(1) FROM information_schema.tables " +
                    "WHERE table_schema = current_schema() AND table_name = LOWER(?)";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, tableName.toLowerCase());
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean columnExists(JdbcTemplate jdbcTemplate, String tableName, String columnName) {
        try {
            String sql = "SELECT COUNT(1) FROM information_schema.columns " +
                    "WHERE table_schema = current_schema() " +
                    "AND table_name = LOWER(?) AND column_name = LOWER(?)";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class,
                    tableName.toLowerCase(), columnName.toLowerCase());
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String generateAddColumnSql(String tableName, String columnName,
                                       String columnLabel, String columnType, String comment) {
        String sql = String.format("ALTER TABLE \"%s\" ADD COLUMN \"%s\" %s",
                tableName.toLowerCase(), columnName.toLowerCase(), columnType);

        if (StringUtils.isNotBlank(comment)) {
            sql += ";\nCOMMENT ON COLUMN \"" + tableName.toLowerCase() + "\".\"" +
                    columnName.toLowerCase() + "\" IS '" + comment + "'";
        }

        return sql;
    }

    @Override
    public String generateModifyColumnSql(String tableName, String columnName,
                                          String columnLabel, String columnType, String comment) {
        return String.format("ALTER TABLE \"%s\" ALTER COLUMN \"%s\" TYPE %s",
                tableName.toLowerCase(), columnName.toLowerCase(), columnType);
    }

    @Override
    public String getTextType() {
        return "TEXT";
    }

    @Override
    public String getStringType(int length) {
        return length <= 10485760 ?
                String.format("VARCHAR(%d)", length) : "TEXT";
    }

    @Override
    public String getBooleanType() {
        return "BOOLEAN";
    }

    @Override
    public Integer getRecordCount(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = String.format("SELECT COUNT(1) FROM \"%s\"", tableName.toLowerCase());
            return jdbcTemplate.queryForObject(sql, Integer.class);
        } catch (Exception e) {
            return 0;
        }
    }


    @Override
    public String getPaginationSql(String sql, int offset, int limit) {
        return sql + " LIMIT " + limit + " OFFSET " + offset;
    }

    @Override
    public String getCurrentTimeFunction() {
        return "NOW()";
    }

    @Override
    public String getCurrentDateFunction() {
        return "CURRENT_DATE";
    }
}
