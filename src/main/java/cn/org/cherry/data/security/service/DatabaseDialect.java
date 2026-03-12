package cn.org.cherry.data.security.service;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * 数据库方言接口
 */
public interface DatabaseDialect {

    /**
     * 检查表是否存在
     */
    boolean tableExists(JdbcTemplate jdbcTemplate, String tableName);

    /**
     * 检查列是否存在
     */
    boolean columnExists(JdbcTemplate jdbcTemplate, String tableName, String columnName);

    /**
     * 生成添加列的SQL语句
     */
    String generateAddColumnSql(String tableName, String columnName,
                                String columnLabel, String columnType, String comment);

    /**
     * 生成修改列的SQL语句
     */
    String generateModifyColumnSql(String tableName, String columnName,
                                   String columnLabel, String columnType, String comment);

    /**
     * 获取文本类型
     */
    String getTextType();

    /**
     * 获取字符串类型
     */
    String getStringType(int length);

    /**
     * 获取布尔类型
     */
    String getBooleanType();

    /**
     * 获取记录数
     */
    Integer getRecordCount(JdbcTemplate jdbcTemplate, String tableName);

    /**
     * 获取分页SQL
     */
    String getPaginationSql(String sql, int offset, int limit);

    /**
     * 获取当前时间函数
     */
    String getCurrentTimeFunction();

    /**
     * 获取当前日期函数
     */
    String getCurrentDateFunction();
}
