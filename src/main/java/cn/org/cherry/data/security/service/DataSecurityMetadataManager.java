package cn.org.cherry.data.security.service;

import cn.org.cherry.data.security.annotation.EncryptField;
import cn.org.cherry.data.security.annotation.IdentificationCode;
import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.config.DataSecurityProperties;
import cn.org.cherry.data.security.config.DataSecurityRuoYiProperties;
import cn.org.cherry.data.security.config.DataSecurityYuDaoProperties;
import cn.org.cherry.data.security.entity.DataSecurityMetadata;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.info.EnhancedEntityMetaInfo;
import cn.org.cherry.data.security.service.dialect.*;
import cn.org.cherry.data.security.strategy.EncryptionStrategy;
import cn.org.cherry.data.security.strategy.IdentificationCodeStrategy;
import cn.org.cherry.data.security.strategy.StrategyManager;
import cn.org.cherry.data.security.utils.DataSecurityUtils;
import cn.org.cherry.data.security.utils.EntityScanner;
import cn.org.cherry.data.security.utils.MapperGenericFinder;
import com.alibaba.fastjson.JSON;
import com.baomidou.mybatisplus.annotation.DbType;
import com.baomidou.mybatisplus.annotation.FieldStrategy;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.toolkit.JdbcUtils;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.DigestUtils;

import javax.sql.DataSource;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 多数据库兼容的字段管理器
 */
@Slf4j
@Service
public class DataSecurityMetadataManager {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private DataSecurityProperties properties;

    @Autowired
    private DataSecurityRuoYiProperties ruoYiProperties;

    @Autowired
    private DataSecurityYuDaoProperties yuDaoProperties;

    @Autowired
    private DataSecurityMetadataService metadataService;

    @Autowired
    private DataSecurityTaskService taskService;

    @Autowired
    private StrategyManager strategyManager;

    private DatabaseDialect databaseDialect;

    @Autowired
    private ConfigurationResolver configurationResolver;

    @Autowired
    private DataSecurityCommonService dataSecurityCommonService;

    @Autowired(required = false)
    private List<BaseMapper<?>> mappers = new ArrayList<>();

    // 缓存：表名 -> 实体类Class
    private final Map<String, Class<?>> tableEntityCache = new ConcurrentHashMap<>();

    // 缓存：实体类名 -> 表名
    private final Map<Class<?>, String> entityTableCache = new ConcurrentHashMap<>();

    // 线程池，用于异步重新生成数据
    private final ExecutorService executorService = Executors.newFixedThreadPool(5);

    // 数据库方言映射
    private static final Map<DbType, DatabaseDialect> DIALECT_MAP = new EnumMap<>(DbType.class);

    // 启动类
    private static Class<?> APPLICATION_CLASS = null;

    // 实体元信息缓存 - 使用 Caffeine 缓存，设置最大容量和过期时间
    private static final Cache<Class<?>, EnhancedEntityMetaInfo> ENTITY_META_CACHE =
            Caffeine.newBuilder()
                    .maximumSize(500)
                    .expireAfterWrite(1, java.util.concurrent.TimeUnit.HOURS)
                    .build();

    // 支持的数据库类型
    private static final Set<DbType> SUPPORTED_DATABASES = new HashSet<>(Arrays.asList(
            DbType.MYSQL,
            DbType.MARIADB,
            DbType.ORACLE,
            DbType.POSTGRE_SQL,
            DbType.SQL_SERVER,
            DbType.SQLITE,
            DbType.H2,
            DbType.DM,      // 达梦
            DbType.KINGBASE_ES, // 人大金仓
            DbType.OSCAR,   // 神通数据库
            DbType.GAUSS,   // 高斯数据库
            DbType.CLICK_HOUSE,
            DbType.DB2,
            DbType.HSQL,
            DbType.SYBASE
    ));

    public void init() {


        //初始化启动类参数
        log.info("=============================================");
        initApplicationClass();
        log.info("========== 数据安全插件 启动类参数 完成 ==========");

        //初始化数据表实体映射关系
        initEntityTableMapping();
        log.info("========== 数据安全插件 实体类映射 完成 ==========");
        // 初始化数据库方言
        initDatabaseDialects();
        log.info("========== 数据安全插件 初始化方言 开始 ==========");
        // 检测数据库类型
        detectDatabaseType();
        log.info("========== 数据安全插件 初始化方言 完成 ==========");
        log.info("=============================================");
        // 根据配置决定是否启动时执行
        log.info("========== 数据安全插件 元数据处理 开始 ==========");
        initIdentificationCodeMetadata();
        log.info("========== 数据安全插件 元数据处理 结束 ==========");
        log.info("=============================================");
        // 处理数据
        initIdentificationCodeAndEncryptData(true);
        log.info("=============================================");
    }

    /**
     * 处理鉴别码元数据表和相关数据库字段的创建
     */
    public void initIdentificationCodeMetadata() {
        if (properties.getAutoCreate().isEnabled()) {
            scanAllEntitiesAndHandleMetadata();
        }
    }

    private void initApplicationClass() {
        APPLICATION_CLASS = EntityScanner.findSpringBootApplicationClass();
    }

    public void initIdentificationCodeAndEncryptData() {
        initIdentificationCodeAndEncryptData(false);
    }

    public void initIdentificationCodeAndEncryptData(boolean checkTenant) {
        if (!properties.getAutoCreate().isAutoHandleDataEnable()) {
            return;
        }
        if (properties.getAutoCreate().isAutoHandleDataAsync()) {
            initIdentificationCodeAndEncryptDataAsync(checkTenant);
        } else {
            processAllEntitiesIdentificationCodeAndEncryptData(checkTenant);
        }
    }

    @Async
    public void initIdentificationCodeAndEncryptDataAsync(boolean checkTenant) {
        processAllEntitiesIdentificationCodeAndEncryptData(checkTenant);
    }

    public EnhancedEntityMetaInfo getEnhancedEntityMetaInfo(Class<?> entityClass) {
        return ENTITY_META_CACHE.get(entityClass, clazz -> {
            EnhancedEntityMetaInfo metaInfo = new EnhancedEntityMetaInfo();
            metaInfo.setEntityClass(clazz);

            String primaryKeyField = DataSecurityUtils.getPrimaryKeyField(entityClass);
            String primaryKeyColumn = DataSecurityUtils.camelToUnderscore(primaryKeyField);
            metaInfo.setPrimaryKeyColumn(primaryKeyColumn);
            metaInfo.setTableName(getTableNameByClazz(entityClass));

            // 收集字段信息
            Map<String, Field> fieldMap = new HashMap<>();
            Map<String, EncryptField> encryptFieldMap = new HashMap<>();
            Map<String, ConfigurationResolver.MergedEncryptField> mergedEncryptFieldMap = new HashMap<>();
            Map<Field, FieldStrategy> fieldUpdateStrategyMap = new HashMap<>();
            Map<Field, FieldStrategy> fieldInsertStrategyMap = new HashMap<>();

            List<Field> allFields = getAllFields(clazz);
            for (Field field : allFields) {
                field.setAccessible(true);
                String fieldName = field.getName();
                fieldMap.put(fieldName, field);

                // 检查加密注解
                EncryptField encryptAnnotation = field.getAnnotation(EncryptField.class);
                if (encryptAnnotation != null) {
                    encryptFieldMap.put(fieldName, encryptAnnotation);
                    // 解析合并后的加密配置
                    ConfigurationResolver.MergedEncryptField mergedConfig =
                            configurationResolver.resolve(encryptAnnotation);
                    mergedEncryptFieldMap.put(fieldName, mergedConfig);
                }

                TableField tableFieldAnnotation = field.getAnnotation(TableField.class);
                if (tableFieldAnnotation != null) {
                    fieldUpdateStrategyMap.put(field, tableFieldAnnotation.updateStrategy());
                    fieldInsertStrategyMap.put(field, tableFieldAnnotation.insertStrategy());
                }else{
                    fieldUpdateStrategyMap.put(field, FieldStrategy.DEFAULT);
                    fieldInsertStrategyMap.put(field, FieldStrategy.DEFAULT);
                }
            }
            metaInfo.setFieldUpdateStrategyMap(fieldUpdateStrategyMap);
            metaInfo.setFieldInsertStrategyMap(fieldInsertStrategyMap);
            metaInfo.setFieldMap(fieldMap);
            metaInfo.setEncryptFieldMap(encryptFieldMap);
            metaInfo.setMergedEncryptFieldMap(mergedEncryptFieldMap);

            // 检查鉴别码注解
            IdentificationCode idCodeAnnotation = clazz.getAnnotation(IdentificationCode.class);
            if (idCodeAnnotation != null) {
                metaInfo.setIdentificationCodeAnnotation(idCodeAnnotation);

                // 解析合并后的鉴别码配置
                ConfigurationResolver.MergedIdentificationCode mergedConfig =
                        configurationResolver.resolve(idCodeAnnotation);
                metaInfo.setMergedIdentificationConfig(mergedConfig);

                // 设置鉴别码相关字段
                Field contentField = fieldMap.get(DataSecurityUtils.underscoreToCamel(mergedConfig.getContentField()));
                Field codeField = fieldMap.get(DataSecurityUtils.underscoreToCamel(mergedConfig.getCodeField()));
                Field checkResultField = fieldMap.get(mergedConfig.getCheckResultField());

                metaInfo.setIdentificationContentField(contentField);
                metaInfo.setIdentificationCodeField(codeField);
                metaInfo.setCheckResultField(checkResultField);
            }

            return metaInfo;
        });
    }

    /**
     * 根据数据表名获取实体类信息
     * @param tableName 数据表名
     * @return 实体类信息
     */
    public Class<?> getClazzByTableName(String tableName) {
        if (StringUtils.isBlank(tableName)) {
            return null;
        }
        // 先从缓存获取
        Class<?> clazz = tableEntityCache.get(tableName);
        if (clazz != null) {
            return clazz;
        }
        // 如果缓存没有，扫描实体类获取
        List<Class<?>> entityClasses = EntityScanner.scanEntitiesWithAnnotation(
                TableName.class, APPLICATION_CLASS
        );
        for (Class<?> entityClass : entityClasses) {
            String tName = getTableName(entityClass);
            if (tableName.equalsIgnoreCase(tName)) {
                // 放入缓存
                tableEntityCache.put(tableName, entityClass);
                entityTableCache.put(entityClass, tableName);
                return entityClass;
            }
        }
        return null;
    }

    /**
     * 根据实体类获取数据表名
     * @param clazz 实体类信息
     * @return 数据表名
     */
    public String getTableNameByClazz(Class<?> clazz) {
        if (clazz == null) {
            return null;
        }
        // 先从缓存获取
        String tableName = entityTableCache.get(clazz);
        if (tableName != null) {
            return tableName;
        }
        // 如果缓存没有，扫描实体类获取
        List<Class<?>> entityClasses = EntityScanner.scanEntitiesWithAnnotation(
                TableName.class, APPLICATION_CLASS
        );
        for (Class<?> entityClass : entityClasses) {
            if (entityClass.equals(clazz)) {
                String tName = getTableName(entityClass);
                // 放入缓存
                tableEntityCache.put(tName, entityClass);
                entityTableCache.put(entityClass, tName);
                return tName;
            }
        }
        return null;
    }

    /**
     * 初始化数据库方言
     */
    private void initDatabaseDialects() {
        DIALECT_MAP.put(DbType.MYSQL, new MySQLDialect());
        DIALECT_MAP.put(DbType.MARIADB, new MySQLDialect());
        DIALECT_MAP.put(DbType.ORACLE, new OracleDialect());
        DIALECT_MAP.put(DbType.POSTGRE_SQL, new PostgreSQLDialect());
        DIALECT_MAP.put(DbType.SQL_SERVER, new SQLServerDialect());
        DIALECT_MAP.put(DbType.SQLITE, new SQLiteDialect());
        DIALECT_MAP.put(DbType.H2, new H2Dialect());
        DIALECT_MAP.put(DbType.DM, new DMDialect());
        DIALECT_MAP.put(DbType.KINGBASE_ES, new KingbaseESDialect());
        DIALECT_MAP.put(DbType.OSCAR, new OscarDialect());
//        DIALECT_MAP.put(DbType.GAUSS, new GaussDialect());
//        DIALECT_MAP.put(DbType.CLICK_HOUSE, new ClickHouseDialect());
//        DIALECT_MAP.put(DbType.DB2, new DB2Dialect());
//        DIALECT_MAP.put(DbType.HSQL, new HSQLDialect());
//        DIALECT_MAP.put(DbType.SYBASE, new SybaseDialect());
    }

    /**
     * 检测数据库类型
     */
    private void detectDatabaseType() {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metaData = connection.getMetaData();
            String databaseProductName = metaData.getDatabaseProductName();
            String url = metaData.getURL();

            // 使用MyBatis-Plus的JdbcUtils检测数据库类型
            DbType dbType = JdbcUtils.getDbType(url);

            if (!SUPPORTED_DATABASES.contains(dbType)) {
                log.info("=== 警告: 不支持的数据库类型: {}, 使用MySQL方言作为默认", dbType);
                dbType = DbType.MYSQL;
            }

            databaseDialect = DIALECT_MAP.get(dbType);
            if (databaseDialect == null) {
                databaseDialect = new MySQLDialect(); // 默认使用MySQL方言
            }

            log.info("=== 数据库类型: {}, 使用方言: {}", dbType, databaseDialect.getClass().getSimpleName());

        } catch (SQLException e) {
            throw new RuntimeException("检测数据库类型失败: " + e.getMessage(), e);
        }
    }

    /**
     * 处理所有实体类
     */
    public void scanAllEntitiesAndHandleMetadata() {
        try {
            // 扫描所有带有@IdentificationCode注解的实体类
            List<Class<?>> entityClasses = EntityScanner.scanEntitiesWithAnnotation(IdentificationCode.class, APPLICATION_CLASS);

            log.info("=== 处理实体类提示：找到 {} 个需要处理的实体类", entityClasses.size());

            for (Class<?> entityClass : entityClasses) {
                try {
                    handleMetadataByEntityClazz(entityClass);
                } catch (Exception e) {
                    log.info("=== 处理实体类失败: {}, 错误: {}", entityClass.getSimpleName(), e.getMessage());
                    // 继续处理下一个实体类
                    log.error(e.getMessage(), e);
                }
            }
        } catch (Exception e) {
            log.info("=== 处理实体类时发生错误: " + e.getMessage());
            log.error(e.getMessage(), e);
        }
    }

    /**
     * 处理单个实体类
     * <p>
     * 使用事务确保元数据操作和数据一致性。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public void handleMetadataByEntityClazz(Class<?> entityClass) {
        if (!entityClass.isAnnotationPresent(IdentificationCode.class)) {
            return;
        }
        // 获取表名（支持多种方式）
        String tableName = getTableName(entityClass);
        if (StringUtils.isBlank(tableName)) {
            log.info("=== 处理实体类失败：实体类 {} 无法获取表名，跳过处理", entityClass.getSimpleName());
            return;
        }

        // 检查表是否存在
        if (!tableExists(tableName)) {
            log.info("=== 处理实体类失败：实体类 {} 数据表 {} 不存在不存在，跳过处理", entityClass.getSimpleName(), tableName);
            return;
        }

        // 获取配置
        IdentificationCode annotation = entityClass.getAnnotation(IdentificationCode.class);
        ConfigurationResolver.MergedIdentificationCode config = configurationResolver.resolve(annotation);

        if (!config.isEnabled()) {
            log.info("=== 处理实体类失败：实体类 {} 数据表 {} ，鉴别码功能已禁用，跳过处理", entityClass.getSimpleName(), tableName);
            return;
        }

        // 检查字段是否需要创建
        boolean needCreateContentField = StringUtils.isNotBlank(config.getContentField()) && !columnExists(tableName, config.getContentField());
        boolean needCreateCodeField = !columnExists(tableName, config.getCodeField());

        // 获取或创建元数据
        DataSecurityMetadata metadata = metadataService.getByTableName(tableName);
        boolean isNewMetadata = metadata == null;

        if (isNewMetadata) {
            metadata = createNewMetadata(tableName, entityClass, config);
        }

        // 计算include字段的哈希值
        String includeFieldsJson = convertIncludeFieldsToJson(config.getIncludeFields());
        String includeFieldsHash = calculateHash(includeFieldsJson);

        // 检查include字段是否有变化
        boolean includeFieldsChanged = checkIncludeFieldsChanged(metadata, includeFieldsHash);

        // 更新元数据
        metadata.setIncludeFieldsHash(includeFieldsHash);
        metadata.setIncludeFieldsJson(includeFieldsJson);
        metadata.setIncludeFieldsChanged(includeFieldsChanged);
        //如果仅仅需要创建content字段的话则暂时不重新生成，因为不影响鉴别码逻辑
        metadata.setNeedRegenerate(includeFieldsChanged || needCreateCodeField || !metadata.getDataRegenerated());
        metadata.setUpdatedTime(LocalDateTime.now());
        if (isNewMetadata) {
            // 获取记录数
            Integer recordCount = getRecordCount(tableName);
            metadata.setRecordCount(recordCount);
            metadata.setCreatedTime(LocalDateTime.now());
            metadataService.save(metadata);
        } else {
            metadataService.updateById(metadata);
        }

        // 创建字段（如果需要）
        if (needCreateContentField || needCreateCodeField) {

            //创建配置了鉴别码注解的数据表的字段信息
            createIdentificationFields(tableName, config, needCreateContentField, needCreateCodeField);
            log.info("=== 处理实体类提示：实体类 {} 数据表 {} ，鉴别码字段创建完成", entityClass.getSimpleName(), tableName);

            // 更新字段创建状态
            metadata.setFieldCreated(true);
            metadataService.updateById(metadata);
        }
        log.info("=== 处理实体类提示：实体类 {} 数据表 {} ，元数据处理完成", entityClass.getSimpleName(), tableName);
    }

    public void initEntityTableMapping() {
        // 扫描所有带有@TableName注解的实体类
        List<Class<?>> entityClasses = EntityScanner.scanEntitiesWithAnnotation(TableName.class, APPLICATION_CLASS);
        for (Class<?> entityClass : entityClasses) {
            String tableName = getTableName(entityClass);
            if (StringUtils.isNotBlank(tableName)) {
                tableEntityCache.put(tableName, entityClass);
                entityTableCache.put(entityClass, tableName);
                //初始化实体元数据
                getEnhancedEntityMetaInfo(entityClass);
            }
        }
    }

    public void processAllEntitiesIdentificationCodeAndEncryptData(boolean checkTenant) {
        log.info("==========  数据安全插件 数据处理 开始  ==========");
        for (Class<?> clazz : entityTableCache.keySet()) {
            try {
                EnhancedEntityMetaInfo metaInfo = getEnhancedEntityMetaInfo(clazz);
                if (metaInfo.hasIdentificationCode() || metaInfo.hasEncryptFields()) {
                    processIdentificationCodeAndEncryptData(metaInfo, checkTenant);
                }
            } catch (Exception e) {
                log.info("=== 处理实体类失败: {}, 错误: {}", clazz.getSimpleName(), e.getMessage());
                // 继续处理下一个实体类
                log.error(e.getMessage(), e);
            }
        }
        log.info("==========  数据安全插件 数据处理 结束  ==========");
    }

    public void processIdentificationCodeAndEncryptData(EnhancedEntityMetaInfo metaInfo, boolean checkTenant) {
        // 获取表名（支持多种方式）
        String tableName = getTableNameByClazz(metaInfo.getEntityClass());
        if (StringUtils.isBlank(tableName)) {
            log.info("=== 处理实体类失败：实体类 {} 无法获取表名，跳过处理", metaInfo.getEntityClass().getSimpleName());
            return;
        }
        // 检查表是否存在
        if (!tableExists(tableName)) {
            log.info("=== 处理实体类失败：实体类 {} 数据表 {} 不存在不存在，跳过处理", metaInfo.getEntityClass().getSimpleName(), tableName);
            return;
        }
        if (checkTenant && ruoYiProperties.getEnable() && !ruoYiProperties.getIgnoreTables().contains(tableName)) {
            log.info("=== 处理实体类失败：实体类 {} 数据表 {} 是多租户数据表，跳过处理", metaInfo.getEntityClass().getSimpleName(), tableName);
            return;
        }
        if (checkTenant && yuDaoProperties.getEnable() && !yuDaoProperties.getIgnoreTables().contains(tableName)) {
            log.info("=== 处理实体类失败：实体类 {} 数据表 {} 是多租户数据表，跳过处理", metaInfo.getEntityClass().getSimpleName(), tableName);
            return;
        }
        if (metaInfo.hasIdentificationCode()) {
            log.info("=== 处理鉴别码数据：实体类 {} 数据表 {} 开始", metaInfo.getEntityClass().getSimpleName(), tableName);
            ConfigurationResolver.MergedIdentificationCode config = metaInfo.getMergedIdentificationConfig();
            // 检查字段是否需要创建
//            boolean needCreateContentField = StringUtils.isNotBlank(config.getContentField()) &&!columnExists(tableName, config.getContentField());
            boolean needCreateCodeField = !columnExists(tableName, config.getCodeField());
            // 获取或创建元数据
            DataSecurityMetadata metadata = metadataService.getByTableName(tableName);
            if (metadata != null) {
                // 计算include字段的哈希值
                String includeFieldsJson = convertIncludeFieldsToJson(config.getIncludeFields());
                String includeFieldsHash = calculateHash(includeFieldsJson);

                // 检查include字段是否有变化
                boolean includeFieldsChanged = checkIncludeFieldsChanged(metadata, includeFieldsHash);

                // 是否需要全量重新生成数据
                metadata.setNeedRegenerate(includeFieldsChanged || needCreateCodeField || !metadata.getDataRegenerated());
                //执行更新
                handleIdentificationCodeRegenerateData(tableName, metaInfo.getEntityClass(), metadata, config, metadata.getNeedRegenerate());
            }
            //打印结果
            log.info("=== 处理鉴别码数据：实体类 {} 数据表 {} 结束", metaInfo.getEntityClass().getSimpleName(), tableName);
        }
        if (metaInfo.hasEncryptFields()) {
            //处理加密字段
            handleEncryptFieldData(metaInfo);
        }
    }

    /**
     * 处理加密字段数据
     * <p>
     * 使用事务确保加密操作的数据一致性。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public void handleEncryptFieldData(EnhancedEntityMetaInfo metaInfo) {
        String tableName = metaInfo.getTableName();
        log.info("=== 处理加密字段数据：实体类 {} 数据表 {} 开始", metaInfo.getEntityClass().getSimpleName(), tableName);
        DataSecurityTask task = createEncryptTask(metaInfo.getTableName());
        try {
            // 获取实体类的Mapper
            BaseMapper<?> mapper = findMapperForEntity(metaInfo.getEntityClass());
            if (mapper == null) {
                log.info("=== 处理加密字段失败：实体类 {} 数据表 {} 找不到实体类对应的Mapper", metaInfo.getEntityClass().getSimpleName(), tableName);
                return;
            }
            EncryptionStrategy strategy = getEncryptionStrategy(configurationResolver.getEncryptionConfig());
            String prefix = strategy.getEncryptPrefix();

            int pageSize = properties.getAutoCreate().getBatchSize();
            IPage<Map<String, Object>> pageInfo = new Page<>(1, pageSize);
            QueryWrapper<Map<String, Object>> queryWrapper = new QueryWrapper<>();

            Iterator<String> iterator = metaInfo.getEncryptFieldMap().keySet().iterator();
            if (iterator.hasNext()) {
                // 第一个元素
                queryWrapper.notLike(DataSecurityUtils.camelToUnderscore(iterator.next()), prefix + "%");
                // 后续元素
                while (iterator.hasNext()) {
                    queryWrapper.or().notLike(DataSecurityUtils.camelToUnderscore(iterator.next()), prefix + "%");
                }
            }
            // 获取主键字段名
            String primaryKeyColumn = metaInfo.getPrimaryKeyColumn();

            // 分页处理数据
            int totalProcessed = 0;
            int successCount = 0;
            int failedCount = 0;

            int count = 0;
            while (true) {
                // 分页查询数据
                IPage<Map<String, Object>> pageResult = dataSecurityCommonService.selectPage(tableName, pageInfo, queryWrapper);
                if (pageResult == null || pageResult.getRecords() == null || pageResult.getRecords().isEmpty()) {
                    break;
                }
                if (count == 0) {
                    task.setTotalRecords((int) pageResult.getTotal());
                }
                // 批量处理
                for (Map<String, Object> dataMap : pageResult.getRecords()) {
                    Object id = dataMap.get(primaryKeyColumn);
                    if (id == null) {
                        continue;
                    }
                    try {
                        //循环获取字段
                        UpdateWrapper<Map<String, Object>> updateWrapper = new UpdateWrapper<>();
                        boolean needUpdate = false;
                        for (String fieldName : metaInfo.getEncryptFieldMap().keySet()) {
                            String columnName = DataSecurityUtils.camelToUnderscore(fieldName);
                            Object fieldValue = dataMap.get(columnName);
                            if (fieldValue != null && !fieldValue.toString().startsWith(prefix)) {
                                String ciphertext = strategy.encrypt(fieldValue.toString());
                                updateWrapper.set(columnName, ciphertext);
                                needUpdate = true;
                            }
                        }
                        if (!needUpdate) {
                            continue;
                        }
                        updateWrapper.eq(primaryKeyColumn, id);
                        // 更新数据库
                        dataSecurityCommonService.updateByWrapper(tableName, updateWrapper);
                        successCount++;

                    } catch (Exception e) {
                        failedCount++;
                        // 记录错误，但不中断
                        log.info("=== 处理加密字段数据：实体类 {} 数据表 {} ID：{} 错误：{}", metaInfo.getEntityClass().getSimpleName(), tableName, id, e.getMessage());
                        log.error("数据加密失败, ID: " + id, e);
                    }
                    totalProcessed++;
                    // 每处理100条更新一次任务进度
                    if (totalProcessed % 100 == 0) {
                        updateTaskProgress(task, totalProcessed, successCount, failedCount);
                    }
                }
                count++;
            }

            // 更新任务状态为完成
            task.setTaskStatus(DataSecurityTask.TaskStatus.COMPLETED.name());
            task.setEndTime(LocalDateTime.now());
            task.setProcessedRecords(totalProcessed);
            task.setSuccessRecords(successCount);
            task.setFailedRecords(failedCount);
            taskService.updateById(task);

            //打印执行结果
            log.info("=== 处理加密字段数据：实体类 {} 数据表 {} 处理加密数据：{} 条, 成功: {} 条, 失败: {} 条。", metaInfo.getEntityClass().getSimpleName(), tableName, totalProcessed, successCount, failedCount);


        } catch (Exception e) {
            // 更新任务状态为失败
            task.setTaskStatus(DataSecurityTask.TaskStatus.FAILED.name());
            task.setEndTime(LocalDateTime.now());
            task.setErrorMessage(e.getMessage());
            taskService.updateById(task);
            log.error("处理加密数据失败: {}", e.getMessage(), e);
        }
        log.info("=== 处理加密字段数据：实体类 {} 数据表 {} 结束", metaInfo.getEntityClass().getSimpleName(), tableName);
    }

    /**
     * 获取表名（支持多种ORM框架）
     */
    private String getTableName(Class<?> entityClass) {
        // 1. 尝试从MyBatis-Plus的@TableName注解获取
        TableName tableNameAnnotation = entityClass.getAnnotation(TableName.class);
        if (tableNameAnnotation != null && StringUtils.isNotBlank(tableNameAnnotation.value())) {
            return tableNameAnnotation.value();
        }

//        // 2. 尝试从JPA的@Table注解获取
//        jakarta.persistence.Table jpaTableAnnotation = entityClass.getAnnotation(jakarta.persistence.Table.class);
//        if (jpaTableAnnotation != null && StringUtils.isNotBlank(jpaTableAnnotation.name())) {
//            return jpaTableAnnotation.name();
//        }
//
//        // 3. 尝试从javax.persistence的@Table注解获取
//        javax.persistence.Table javaxTableAnnotation = entityClass.getAnnotation(javax.persistence.Table.class);
//        if (javaxTableAnnotation != null && StringUtils.isNotBlank(javaxTableAnnotation.name())) {
//            return javaxTableAnnotation.name();
//        }

        // 4. 尝试从MyBatis-Plus的全局配置获取表名前缀
        String tablePrefix = getTablePrefixFromConfig();
        if (StringUtils.isNotBlank(tablePrefix)) {
            return tablePrefix + camelToUnderscore(entityClass.getSimpleName());
        }

        // 5. 默认：将类名转换为下划线格式
        return camelToUnderscore(entityClass.getSimpleName());
    }

    /**
     * 驼峰转下划线
     */
    private String camelToUnderscore(String str) {
        if (StringUtils.isBlank(str)) {
            return str;
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (Character.isUpperCase(c)) {
                if (i > 0) {
                    result.append('_');
                }
                result.append(Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * 从配置获取表名前缀
     */
    private String getTablePrefixFromConfig() {
        // 这里可以从配置文件中读取
        // 例如：mybatis-plus.global-config.db-config.table-prefix
        return "";
    }

    /**
     * 检查表是否存在
     */
    private boolean tableExists(String tableName) {
        return databaseDialect.tableExists(jdbcTemplate, tableName);
    }

    /**
     * 检查列是否存在
     */
    private boolean columnExists(String tableName, String columnName) {
        if (StringUtils.isBlank(columnName)) {
            return false;
        }
        return databaseDialect.columnExists(jdbcTemplate, tableName, columnName);
    }

    /**
     * 获取记录数
     */
    private Integer getRecordCount(String tableName) {
        return databaseDialect.getRecordCount(jdbcTemplate, tableName);
    }

    /**
     * 创建鉴别码字段
     */
    private void createIdentificationFields(String tableName,
                                            ConfigurationResolver.MergedIdentificationCode config,
                                            boolean createContentField,
                                            boolean createCodeField) {

        try {
            List<String> sqlStatements = new ArrayList<>();

            // 生成创建字段的SQL语句
            if (createContentField) {
                String contentFieldSql = databaseDialect.generateAddColumnSql(
                        tableName,
                        config.getContentField(),
                        "",
                        getContentFieldType(),
                        getContentFieldComment()
                );
                sqlStatements.add(contentFieldSql);
            }

            if (createCodeField) {
                String codeFieldSql = databaseDialect.generateAddColumnSql(
                        tableName,
                        config.getCodeField(),
                        "identification_code",
                        getCodeFieldType(),
                        getCodeFieldComment()
                );
                sqlStatements.add(codeFieldSql);
            }

            // 执行SQL语句
            for (String sql : sqlStatements) {
                try {
                    jdbcTemplate.execute(sql);
                } catch (Exception e) {
                    log.error("执行SQL失败: {}, 错误: {}", sql, e.getMessage(), e);
                    // 继续执行其他SQL
                }
            }

        } catch (Exception e) {
            throw new RuntimeException("创建鉴别码字段失败: " + e.getMessage(), e);
        }
    }

    /**
     * 根据数据库类型获取内容字段类型
     */
    private String getContentFieldType() {
        return databaseDialect.getTextType();
    }

    /**
     * 根据数据库类型获取鉴别码字段类型
     */
    private String getCodeFieldType() {
        return databaseDialect.getStringType(255);
    }

    /**
     * 根据数据库类型获取校验结果字段类型
     */
    private String getCheckResultFieldType() {
        return databaseDialect.getBooleanType();
    }

    /**
     * 获取内容字段注释
     */
    private String getContentFieldComment() {
        return "鉴别码内容（JSON格式）";
    }

    /**
     * 获取鉴别码字段注释
     */
    private String getCodeFieldComment() {
        return "鉴别码（哈希值）";
    }

    /**
     * 获取校验结果字段注释
     */
    private String getCheckResultFieldComment() {
        return "鉴别码校验结果（0-无效，1-有效）";
    }

    /**
     * 创建新的元数据
     */
    private DataSecurityMetadata createNewMetadata(String tableName, Class<?> entityClass,
                                                   ConfigurationResolver.MergedIdentificationCode config) {
        DataSecurityMetadata metadata = new DataSecurityMetadata();
        metadata.setTableName(tableName);
        metadata.setEntityClass(entityClass.getName());
        metadata.setContentField(config.getContentField());
        metadata.setCodeField(config.getCodeField());
        metadata.setAlgorithm(config.getAlgorithm());
        metadata.setFieldCreated(false);
        metadata.setDataRegenerated(false);
        metadata.setVersion(1);
        return metadata;
    }

    /**
     * 检查include字段是否有变化
     */
    private boolean checkIncludeFieldsChanged(DataSecurityMetadata metadata, String newHash) {
        if (metadata == null) {
            return true; // 新的元数据，需要重新生成
        }

        String oldHash = metadata.getIncludeFieldsHash();
        if (oldHash == null) {
            return true; // 旧的哈希为空，需要重新生成
        }

        return !oldHash.equals(newHash);
    }

    /**
     * 将include字段转换为JSON
     */
    private String convertIncludeFieldsToJson(Set<String> includeFields) {
        try {
            List<String> fieldList = new ArrayList<>(includeFields);
            Collections.sort(fieldList); // 排序，确保顺序一致
            return JSON.toJSONString(fieldList);
        } catch (Exception e) {
            return "[]";
        }
    }

    /**
     * 计算哈希值
     */
    private String calculateHash(String data) {
        return DigestUtils.md5DigestAsHex(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 重新生成数据
     */
    public void handleIdentificationCodeRegenerateData(String tableName, Class<?> entityClass,
                                                       DataSecurityMetadata metadata,
                                                       ConfigurationResolver.MergedIdentificationCode config, boolean needRegenerateData) {

        DataSecurityTask task = createIdentificationCodeTask(tableName, metadata);
        // 使用数据库方言特定的重新生成逻辑
        handleIdentificationCodeRegenerateData(tableName, entityClass, task.getId(), config, needRegenerateData);
    }

    /**
     * 同步重新生成数据
     */
    public void handleIdentificationCodeRegenerateData(String tableName, Class<?> entityClass, Long taskId, ConfigurationResolver.MergedIdentificationCode config, boolean needRegenerateData) {

        DataSecurityTask task = taskService.getById(taskId);
        if (task == null) {
            return;
        }
        try {
            // 更新任务状态为运行中
            task.setTaskStatus(DataSecurityTask.TaskStatus.RUNNING.name());
            task.setStartTime(LocalDateTime.now());
            taskService.updateById(task);

            // 获取实体类的Mapper
            BaseMapper<?> mapper = findMapperForEntity(entityClass);
            if (mapper == null) {
                log.info("=== 处理鉴别码失败：实体类 {} 数据表 {} 找不到实体类对应的Mapper", entityClass.getSimpleName(), tableName);
                return;
            }
            int pageSize = properties.getAutoCreate().getBatchSize();
            IPage<Map<String, Object>> pageInfo = new Page<>(1, pageSize);
            QueryWrapper<Map<String, Object>> queryWrapper = new QueryWrapper<>();
            if (!needRegenerateData) {
                queryWrapper.isNull(config.getCodeField());
            }

            // 获取主键字段名
            String primaryKeyField = DataSecurityUtils.getPrimaryKeyField(entityClass);
            String primaryKeyColumn = camelToSnake(primaryKeyField);

            // 分页处理数据
            int totalProcessed = 0;
            int successCount = 0;
            int failedCount = 0;

            while (true) {
                // 分页查询数据
                IPage<Map<String, Object>> pageResult = dataSecurityCommonService.selectPage(tableName, pageInfo, queryWrapper);
                if (pageResult == null || pageResult.getRecords() == null || pageResult.getRecords().isEmpty()) {
                    break;
                }
                // 批量处理
                for (Map<String, Object> idMap : pageResult.getRecords()) {
                    Object id = idMap.get(primaryKeyColumn);
                    if (id == null) {
                        continue;
                    }
                    try {
                        IdentificationCodeStrategy.IdentificationCodeInfo codeInfo = getIdentificationCodeForEntity(entityClass, idMap, config);

                        UpdateWrapper<Map<String, Object>> updateWrapper = new UpdateWrapper<>();
                        if (StringUtils.isNotBlank(config.getContentField())) {
                            updateWrapper.set(config.getContentField(), codeInfo.getContent());
                        }
                        if (properties.getIdentification().isContentLog()) {
                            log.info("=== 鉴别码原始数据：[{}] {} ", tableName, codeInfo.getContent());
                        }
                        updateWrapper.set(config.getCodeField(), codeInfo.getCode());
                        updateWrapper.eq(primaryKeyColumn, id);
                        // 更新数据库
                        dataSecurityCommonService.updateByWrapper(tableName, updateWrapper);
                        successCount++;

                    } catch (Exception e) {
                        failedCount++;
                        // 记录错误，但不中断
                        log.info("=== 处理鉴别码失败：实体类 {} 数据表 {} ID: {}, 错误: {}", entityClass.getSimpleName(), tableName, id, e.getMessage());
                        log.error("生成鉴别码失败, ID: " + id, e);
                    }

                    totalProcessed++;

                    // 每处理100条更新一次任务进度
                    if (totalProcessed % 100 == 0) {
                        //更新进度
                        updateTaskProgress(task, totalProcessed, successCount, failedCount);
                    }
                }
                //如果是全量生成要 要通过分页进行循环  如果是增量则 每次都查第1页即可
                if (needRegenerateData) {
                    pageInfo = new Page<>(pageInfo.getCurrent() + 1, pageSize);
                }
            }

            // 更新任务状态为完成
            task.setTaskStatus(DataSecurityTask.TaskStatus.COMPLETED.name());
            task.setEndTime(LocalDateTime.now());
            task.setProcessedRecords(totalProcessed);
            task.setSuccessRecords(successCount);
            task.setFailedRecords(failedCount);
            taskService.updateById(task);

            //打印执行结果
            log.info("=== 处理鉴别码统计：实体类 {} 数据表 {}，{}处理数据：{} 条, 成功: {} 条, 失败: {} 条。", entityClass.getSimpleName(), tableName, needRegenerateData ? "[全量]" : "[增量]", totalProcessed, successCount, failedCount);
            // 更新元数据
            updateMetadataAfterRegeneration(tableName, config, successCount);

        } catch (Exception e) {
            // 更新任务状态为失败
            task.setTaskStatus(DataSecurityTask.TaskStatus.FAILED.name());
            task.setEndTime(LocalDateTime.now());
            task.setErrorMessage(e.getMessage());
            taskService.updateById(task);
            log.error("生成鉴别码失败: " + e.getMessage(), e);
        }
    }

    public static Object createEntityWithSpring(Class<?> entityClass,
                                                Map<String, Object> entityDataMap)
            throws Exception {

        // 创建实例
        Object entity = entityClass.getDeclaredConstructor().newInstance();

        // 使用BeanWrapper设置属性
        BeanWrapper beanWrapper = new BeanWrapperImpl(entity);

        for (Map.Entry<String, Object> entry : entityDataMap.entrySet()) {
            String propertyName = entry.getKey();
            Object value = entry.getValue();

            if (beanWrapper.isWritableProperty(propertyName)) {
                // 自动类型转换
                beanWrapper.setPropertyValue(propertyName, value);
            }
        }

        return entity;
    }

    /**
     * 重新生成单个实体的鉴别码
     */
    public IdentificationCodeStrategy.IdentificationCodeInfo getIdentificationCodeForEntity(Class<?> entityClass, Map<String, Object> entityDataMap,
                                                                                            ConfigurationResolver.MergedIdentificationCode config)
            throws Exception {
//        Object entity = createEntityWithSpring(entityClass, entityDataMap);
        // 获取字段映射
        Map<String, Field> fieldMap = new HashMap<>();
        for (Field field : getAllFields(entityClass)) {
            field.setAccessible(true);
            fieldMap.put(field.getName(), field);
        }

        // 收集参与生成鉴别码的数据
        Map<String, Object> dataMap = new LinkedHashMap<>();

        for (String fieldName : config.getIncludeFields()) {
            Field field = fieldMap.get(fieldName);
            if (field == null) {
                continue;
            }
            String columnName = camelToSnake(fieldName);
            if (!entityDataMap.containsKey(columnName)) {
                continue;
            }
            Object value = entityDataMap.get(columnName);
            // 如果是加密字段，需要获取解密后的值
            EncryptField encryptAnnotation = field.getAnnotation(EncryptField.class);
            if (encryptAnnotation != null && value != null) {
                // 获取加密策略
                EncryptionStrategy strategy = getEncryptionStrategy(configurationResolver.getEncryptionConfig());
                // 临时解密用于生成鉴别码
                value = strategy.decrypt(value.toString());
            }
            dataMap.put(columnName, value);
        }

        // 生成鉴别码
        String strategyName = config.getStrategy();
        if (!StringUtils.isNotBlank(strategyName)) {
            strategyName = "defaultIdentificationCodeStrategy";
        }
        IdentificationCodeStrategy strategy = strategyManager.getIdentificationCodeStrategy(strategyName);

        return strategy.generate(dataMap, entityClass.getAnnotation(IdentificationCode.class));
    }

    /**
     * 重新生成单个实体的鉴别码
     */
    private void regenerateIdentificationCodeForEntity(Object entity,
                                                       ConfigurationResolver.MergedIdentificationCode config)
            throws Exception {

        Class<?> entityClass = entity.getClass();

        // 获取字段映射
        Map<String, Field> fieldMap = new HashMap<>();
        for (Field field : getAllFields(entityClass)) {
            field.setAccessible(true);
            fieldMap.put(field.getName(), field);
        }

        // 收集参与生成鉴别码的数据
        Map<String, Object> dataMap = new LinkedHashMap<>();

        for (String fieldName : config.getIncludeFields()) {
            Field field = fieldMap.get(fieldName);
            if (field == null) {
                continue;
            }

            Object value = field.get(entity);

            // 如果是加密字段，需要获取解密后的值
            EncryptField encryptAnnotation = field.getAnnotation(EncryptField.class);
            if (encryptAnnotation != null && value != null) {
                // 获取加密策略
                EncryptionStrategy strategy = getEncryptionStrategy(configurationResolver.getEncryptionConfig());

                // 临时解密用于生成鉴别码
                value = strategy.decrypt(value.toString());
            }

            dataMap.put(fieldName, value);
        }

        // 生成鉴别码
        String strategyName = config.getStrategy();
        if (!StringUtils.isNotBlank(strategyName)) {
            strategyName = "defaultIdentificationCodeStrategy";
        }

        IdentificationCodeStrategy strategy = strategyManager.getIdentificationCodeStrategy(strategyName);

        IdentificationCodeStrategy.IdentificationCodeInfo codeInfo =
                strategy.generate(dataMap, entityClass.getAnnotation(IdentificationCode.class));

        // 设置鉴别码字段
        Field contentField = fieldMap.get(config.getContentField());
        Field codeField = fieldMap.get(config.getCodeField());

        if (contentField != null) {
            contentField.set(entity, codeInfo.getContent());
        }
        if (codeField != null) {
            codeField.set(entity, codeInfo.getCode());
        }
    }


    /**
     * 创建重新生成任务
     */
    private DataSecurityTask createIdentificationCodeTask(String tableName,
                                                          DataSecurityMetadata metadata) {
        DataSecurityTask task = new DataSecurityTask();
        task.setTableName(tableName);
        task.setTaskType(DataSecurityTask.TaskType.IDENTIFICATION_CODE.name());
        task.setTaskStatus(DataSecurityTask.TaskStatus.PENDING.name());
        task.setIncludeFieldsHashBefore(metadata.getIncludeFieldsHash());
        task.setIncludeFieldsHashAfter(metadata.getIncludeFieldsHash());
        task.setTotalRecords(metadata.getRecordCount());
        task.setCreatedBy("SYSTEM");
        task.setCreatedTime(LocalDateTime.now());
        task.setUpdatedTime(LocalDateTime.now());
        taskService.save(task);
        return task;
    }

    private DataSecurityTask createEncryptTask(String tableName) {
        DataSecurityTask task = new DataSecurityTask();
        task.setTableName(tableName);
        task.setTaskType(DataSecurityTask.TaskType.ENCRYPT.name());
        task.setTaskStatus(DataSecurityTask.TaskStatus.RUNNING.name());
        task.setCreatedBy("SYSTEM");
        task.setCreatedTime(LocalDateTime.now());
        task.setUpdatedTime(LocalDateTime.now());
        task.setStartTime(LocalDateTime.now());
        taskService.save(task);
        return task;
    }

    /**
     * 获取实体的所有字段（包括父类）
     */
    private List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        while (clazz != null && clazz != Object.class) {
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            clazz = clazz.getSuperclass();
        }
        return fields;
    }

    /**
     * 根据实体类找到对应的Mapper
     */
    private BaseMapper<?> findMapperForEntity(Class<?> entityClass) {
        for (BaseMapper<?> mapper : mappers) {
            // 通过反射获取Mapper的泛型类型
            try {
                Class<?> mapperEntityClass = MapperGenericFinder.getEntityClassSafely(mapper.getClass());
                if (mapperEntityClass.equals(entityClass)) {
                    return mapper;
                }
            } catch (Exception e) {
                // 忽略错误，继续查找下一个
                log.error(e.getMessage(), e);
            }
        }
        return null;
    }


    /**
     * 更新任务进度
     */
    private void updateTaskProgress(DataSecurityTask task,
                                    int processed, int success, int failed) {
        task.setProcessedRecords(processed);
        task.setSuccessRecords(success);
        task.setFailedRecords(failed);
        task.setUpdatedTime(LocalDateTime.now());
        taskService.updateById(task);
    }

    /**
     * 重新生成后更新元数据
     */
    private void updateMetadataAfterRegeneration(String tableName, ConfigurationResolver.MergedIdentificationCode config, int success) {
        DataSecurityMetadata metadata = metadataService.getByTableName(tableName);
        if (metadata != null) {
            metadata.setDataRegenerated(true);
            metadata.setLastRegenerateTime(new Date());
            metadata.setRegeneratedCount(success);
            String includeFieldsJson = convertIncludeFieldsToJson(config.getIncludeFields());
            String includeFieldsHash = calculateHash(includeFieldsJson);
            metadata.setIncludeFieldsJson(includeFieldsJson);
            metadata.setIncludeFieldsHash(includeFieldsHash);
            metadata.setVersion(metadata.getVersion() + 1);
            metadataService.updateById(metadata);
        }
    }

    //    private EncryptionStrategy getEncryptionStrategy(ConfigurationResolver.MergedEncryptField config) {
//        String strategyName = config.getStrategy();
//        if (!StringUtils.isNotBlank(strategyName)) {
//            strategyName = "defaultEncryptionStrategy";
//        }
//        return strategyManager.getEncryptionStrategy(strategyName);
//    }
    private EncryptionStrategy getEncryptionStrategy(DataSecurityProperties.EncryptionConfig config) {
        String strategyName = config.getStrategy();
        return strategyManager.getEncryptionStrategy(strategyName);
    }

    /**
     * 驼峰转下划线
     */
    private String camelToSnake(String str) {
        if (!StringUtils.isNotBlank(str)) {
            return str;
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (Character.isUpperCase(c)) {
                if (i > 0) {
                    result.append('_');
                }
                result.append(Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
