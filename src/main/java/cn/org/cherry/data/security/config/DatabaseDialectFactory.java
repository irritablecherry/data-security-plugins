package cn.org.cherry.data.security.config;

import cn.org.cherry.data.security.service.DatabaseDialect;
import cn.org.cherry.data.security.service.dialect.*;
import com.baomidou.mybatisplus.annotation.DbType;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.Map;

/**
 * 数据库方言工厂
 */
@Component
public class DatabaseDialectFactory {

    private final Map<DbType, DatabaseDialect> dialectMap = new EnumMap<>(DbType.class);

    public DatabaseDialectFactory() {
        initDialects();
    }

    private void initDialects() {
        dialectMap.put(DbType.MYSQL, new MySQLDialect());
        dialectMap.put(DbType.MARIADB, new MySQLDialect());
        dialectMap.put(DbType.ORACLE, new OracleDialect());
        dialectMap.put(DbType.POSTGRE_SQL, new PostgreSQLDialect());
        dialectMap.put(DbType.SQL_SERVER, new SQLServerDialect());
        dialectMap.put(DbType.SQLITE, new SQLiteDialect());
        dialectMap.put(DbType.H2, new H2Dialect());
        dialectMap.put(DbType.DM, new DMDialect());
        dialectMap.put(DbType.KINGBASE_ES, new KingbaseESDialect());
        dialectMap.put(DbType.OSCAR, new OscarDialect());
//        dialectMap.put(DbType.GAUSS, new GaussDialect());
//        dialectMap.put(DbType.CLICK_HOUSE, new ClickHouseDialect());
//        dialectMap.put(DbType.DB2, new DB2Dialect());
//        dialectMap.put(DbType.HSQL, new HSQLDialect());
//        dialectMap.put(DbType.SYBASE, new SybaseDialect());
    }

    public DatabaseDialect getDialect(DbType dbType) {
        DatabaseDialect dialect = dialectMap.get(dbType);
        if (dialect == null) {
            // 默认使用MySQL方言
            dialect = dialectMap.get(DbType.MYSQL);
        }
        return dialect;
    }

    public DatabaseDialect getDialect(String dbTypeName) {
        try {
            DbType dbType = DbType.getDbType(dbTypeName);
            return getDialect(dbType);
        } catch (Exception e) {
            // 默认使用MySQL方言
            return dialectMap.get(DbType.MYSQL);
        }
    }
}
