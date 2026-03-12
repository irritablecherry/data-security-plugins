package cn.org.cherry.data.security.service.dialect;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.service.DatabaseDialect;
import cn.org.cherry.data.security.service.DataSecurityMetadataManager;
import org.springframework.jdbc.core.JdbcTemplate;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;

/**
 * Oracle数据库方言
 */
public class OracleDialect implements DatabaseDialect {

    @Override
    public boolean tableExists(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = "SELECT COUNT(1) FROM user_tables WHERE table_name = UPPER(?)";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, tableName.toUpperCase());
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean columnExists(JdbcTemplate jdbcTemplate, String tableName, String columnName) {
        try {
            String sql = "SELECT COUNT(1) FROM user_tab_columns " +
                    "WHERE table_name = UPPER(?) AND column_name = UPPER(?)";
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class,
                    tableName.toUpperCase(), columnName.toUpperCase());
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String generateAddColumnSql(String tableName, String columnName,
                                       String columnLabel, String columnType, String comment) {
        // Oracle不支持在ADD COLUMN时添加注释
        String sql = String.format("ALTER TABLE %s ADD %s %s",
                tableName.toUpperCase(), columnName.toUpperCase(), columnType);

        // 添加注释需要单独的SQL
        if (StringUtils.isNotBlank(comment)) {
            sql += ";\nCOMMENT ON COLUMN " + tableName.toUpperCase() + "." +
                    columnName.toUpperCase() + " IS '" + comment + "'";
        }

        return sql;
    }

    @Override
    public String generateModifyColumnSql(String tableName, String columnName,
                                          String columnLabel, String columnType, String comment) {
        return String.format("ALTER TABLE %s MODIFY %s %s",
                tableName.toUpperCase(), columnName.toUpperCase(), columnType);
    }

    @Override
    public String getTextType() {
        return "CLOB";
    }

    @Override
    public String getStringType(int length) {
        return length <= 4000 ?
                String.format("VARCHAR2(%d CHAR)", length) : "CLOB";
    }

    @Override
    public String getBooleanType() {
        return "NUMBER(1)";
    }

    @Override
    public Integer getRecordCount(JdbcTemplate jdbcTemplate, String tableName) {
        try {
            String sql = String.format("SELECT COUNT(1) FROM \"%s\"", tableName.toUpperCase());
            return jdbcTemplate.queryForObject(sql, Integer.class);
        } catch (Exception e) {
            return 0;
        }
    }

    @Override
    public String getPaginationSql(String sql, int offset, int limit) {
        // Oracle使用ROWNUM分页
        return "SELECT * FROM (" +
                "SELECT t.*, ROWNUM rn FROM (" + sql + ") t " +
                "WHERE ROWNUM <= " + (offset + limit) +
                ") WHERE rn > " + offset;
    }

    @Override
    public String getCurrentTimeFunction() {
        return "SYSDATE";
    }

    @Override
    public String getCurrentDateFunction() {
        return "TRUNC(SYSDATE)";
    }
}
