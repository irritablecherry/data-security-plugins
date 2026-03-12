package cn.org.cherry.data.security.service.dialect;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.service.DatabaseDialect;
import cn.org.cherry.data.security.service.DataSecurityMetadataManager;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * SQL Server数据库方言
 */
public class SQLServerDialect implements DatabaseDialect {

    @Override
    public boolean tableExists(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = "SELECT COUNT(1) FROM INFORMATION_SCHEMA.TABLES " +
                    "WHERE TABLE_SCHEMA = SCHEMA_NAME() AND TABLE_NAME = ?";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, tableName);
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean columnExists(JdbcTemplate jdbcTemplate, String tableName, String columnName) {
        try {
            String sql = "SELECT COUNT(1) FROM INFORMATION_SCHEMA.COLUMNS " +
                    "WHERE TABLE_SCHEMA = SCHEMA_NAME() " +
                    "AND TABLE_NAME = ? AND COLUMN_NAME = ?";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, tableName, columnName);
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String generateAddColumnSql(String tableName, String columnName,
                                       String columnLabel, String columnType, String comment) {
        String sql = String.format("ALTER TABLE [%s] ADD [%s] %s NULL",
                tableName, columnName, columnType);

//        if (StringUtils.isNotBlank(comment)) {
//            // SQL Server使用扩展属性来添加注释
//            String schema = getSchemaName(jdbcTemplate);
//            sql += ";\nEXEC sp_addextendedproperty 'MS_Description', '" + comment +
//                    "', 'SCHEMA', '" + schema + "', 'TABLE', '" + tableName +
//                    "', 'COLUMN', '" + columnName + "'";
//        }

        return sql;
    }

    @Override
    public String generateModifyColumnSql(String tableName, String columnName,
                                          String columnLabel, String columnType, String comment) {
        return String.format("ALTER TABLE [%s] ALTER COLUMN [%s] %s NULL",
                tableName, columnName, columnType);
    }

    @Override
    public String getTextType() {
        return "NVARCHAR(MAX)";
    }

    @Override
    public String getStringType(int length) {
        return length <= 4000 ?
                String.format("NVARCHAR(%d)", length) : "NVARCHAR(MAX)";
    }

    @Override
    public String getBooleanType() {
        return "BIT";
    }

    @Override
    public Integer getRecordCount(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = String.format("SELECT COUNT(1) FROM [%s]", tableName);
            return jdbcTemplate.queryForObject(sql, Integer.class);
        } catch (Exception e) {
            return 0;
        }
    }

    @Override
    public String getPaginationSql(String sql, int offset, int limit) {
        // SQL Server 2012+ 使用OFFSET FETCH
        if (sql.toUpperCase().contains("ORDER BY")) {
            return sql + " OFFSET " + offset + " ROWS FETCH NEXT " + limit + " ROWS ONLY";
        } else {
            // 如果没有ORDER BY，添加一个默认的
            return sql + " ORDER BY (SELECT NULL) OFFSET " + offset + " ROWS FETCH NEXT " + limit + " ROWS ONLY";
        }
    }

    @Override
    public String getCurrentTimeFunction() {
        return "GETDATE()";
    }

    @Override
    public String getCurrentDateFunction() {
        return "CAST(GETDATE() AS DATE)";
    }

    private String getSchemaName(JdbcTemplate jdbcTemplate) {
        try {
            return jdbcTemplate.queryForObject("SELECT SCHEMA_NAME()", String.class);
        } catch (Exception e) {
            return "dbo";
        }
    }
}
