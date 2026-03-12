package cn.org.cherry.data.security.interceptor;

import cn.org.cherry.data.security.annotation.EncryptField;
import cn.org.cherry.data.security.annotation.IdentificationCode;
import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.config.DataSecurityProperties;
import cn.org.cherry.data.security.entity.DataSecurityMetadata;
import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.exception.DataSecurityException;
import cn.org.cherry.data.security.info.EnhancedEntityMetaInfo;
import cn.org.cherry.data.security.info.ExtractSetResult;
import cn.org.cherry.data.security.info.SqlOperateType;
import cn.org.cherry.data.security.info.UpdateType;
import cn.org.cherry.data.security.mapper.DataSecurityMetadataMapper;
import cn.org.cherry.data.security.service.DataSecurityMetadataManager;
import cn.org.cherry.data.security.strategy.EncryptionStrategy;
import cn.org.cherry.data.security.strategy.IdentificationCodeStrategy;
import cn.org.cherry.data.security.strategy.StrategyManager;
import cn.org.cherry.data.security.utils.DataDesensitizeUtils;
import cn.org.cherry.data.security.utils.DataSecurityUtils;
import cn.org.cherry.data.security.utils.EntityParameterExtractor;
import cn.org.cherry.data.security.utils.UpdateWrapperParser;
import com.baomidou.mybatisplus.annotation.FieldStrategy;
import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.binding.MapperMethod;
import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.util.*;

/**
 * 支持自定义策略的数据安全插件
 */
@Slf4j
@Intercepts({
        @Signature(type = Executor.class, method = "update", args = {MappedStatement.class, Object.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class, CacheKey.class, BoundSql.class})
})
@Component
public class DataSecurityInterceptor implements Interceptor {

    // 策略管理器
    @Autowired
    private StrategyManager strategyManager;

    @Autowired
    private ConfigurationResolver configurationResolver;

    @Autowired
    private DataSecurityProperties properties;

    @Autowired
    @Lazy
    private DataSecurityMetadataMapper dataSecurityMetadataMapper;

    @Autowired
    @Lazy
    private DataSecurityMetadataManager dataSecurityMetadataManager;


    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        // 检查插件是否启用
        if (!properties.isEnabled()) {
            return invocation.proceed();
        }

        String methodName = invocation.getMethod().getName();
        Object[] args = invocation.getArgs();
        MappedStatement mappedStatement = (MappedStatement) args[0];
        Object parameter = args[1];
        String sql = mappedStatement.getSqlSource().getBoundSql(parameter).getSql();
        String tableName = DataSecurityUtils.extractTableName(sql);
        boolean isSqlUpdate = StringUtils.isNotBlank(sql) && sql.trim().toLowerCase().startsWith("update");
        if ("update".equals(methodName) || isSqlUpdate) {
            return handleUpdate(invocation, mappedStatement, parameter, tableName);
        } else if ("query".equals(methodName)) {
            return handleQuery(invocation, tableName);
        }
        return invocation.proceed();
    }


    private void setIdentificationCodeToEntity(Object entity, EnhancedEntityMetaInfo metaInfo, Map<Field, Object> plaintextDataMap, SqlOperateType operateType, Map<String, Object> oldDataMap) throws Exception {
        ConfigurationResolver.MergedIdentificationCode config = metaInfo.getMergedIdentificationConfig();
        if (!config.isEnabled()) {
            return;
        }
        Field contentField = metaInfo.getIdentificationContentField();
        Field codeField = metaInfo.getIdentificationCodeField();

        if (codeField == null) {
            return;
        }
        IdentificationCodeStrategy.IdentificationCodeInfo codeInfo = getIdentificationCode(entity, metaInfo, plaintextDataMap, operateType, oldDataMap);
        if (codeInfo == null) {
            return;
        }
        if(properties.getIdentification().isContentLog()) {
            // 对敏感数据进行脱敏处理
            String maskedContent = DataDesensitizeUtils.desensitize(codeInfo.getContent(), properties.getIdentification().getDefaultDesensitizeRule());
            log.info("=== 鉴别码原始数据（已脱敏）：[{}] {} ", metaInfo.getTableName(), maskedContent);
        }

        // 设置鉴别码字段
        if (contentField != null) {
            contentField.setAccessible(true);
            contentField.set(entity, codeInfo.getContent());
        }
        codeField.setAccessible(true);
        codeField.set(entity, codeInfo.getCode());
    }

    /**
     * 获取鉴别码接口
     * @param entity 实体数据
     * @param metaInfo 元数据
     * @return 鉴别码对象
     * @throws Exception 异常
     */
    private IdentificationCodeStrategy.IdentificationCodeInfo getIdentificationCode(Object entity,
                                                                                    EnhancedEntityMetaInfo metaInfo,
                                                                                    SqlOperateType operateType,
                                                                                    Map<String, Object> oldDataMap) throws Exception {
        return getIdentificationCode(entity, metaInfo, null, operateType, oldDataMap);
    }

    private IdentificationCodeStrategy.IdentificationCodeInfo getIdentificationCode(Object entity,
                                                                                    EnhancedEntityMetaInfo metaInfo,
                                                                                    Map<Field, Object> plaintextDataMap,
                                                                                    SqlOperateType operateType) throws Exception {
        return getIdentificationCode(entity, metaInfo, plaintextDataMap, operateType, null);

    }

    /**
     * 获取鉴别码接口
     * @param entity 实体数据
     * @param metaInfo 元数据
     * @param plaintextDataMap 明文数据
     * @return 鉴别码对象
     * @throws Exception 异常
     */
    private IdentificationCodeStrategy.IdentificationCodeInfo getIdentificationCode(Object entity,
                                                                                    EnhancedEntityMetaInfo metaInfo,
                                                                                    Map<Field, Object> plaintextDataMap,
                                                                                    SqlOperateType operateType,
                                                                                    Map<String, Object> oldDataMap) throws Exception {
        IdentificationCode annotation = metaInfo.getIdentificationCodeAnnotation();
        ConfigurationResolver.MergedIdentificationCode config = metaInfo.getMergedIdentificationConfig();

        if (!config.isEnabled()) {
            return null;
        }
        Field codeField = metaInfo.getIdentificationCodeField();
        if (codeField == null) {
            return null;
        }
        // 收集参与生成鉴别码的数据
        Map<String, Object> dataMap = collectDataForIdentification(entity, metaInfo, config, plaintextDataMap, operateType, oldDataMap);
        // 使用指定的策略
        IdentificationCodeStrategy strategy = strategyManager.getIdentificationCodeStrategy(config.getStrategy());
        return strategy.generate(dataMap, annotation);
    }

    private Map<String, Object> collectDataForIdentification(Object entity,
                                                             EnhancedEntityMetaInfo metaInfo,
                                                             ConfigurationResolver.MergedIdentificationCode config,
                                                             Map<Field, Object> plaintextDataMap, SqlOperateType operateType,
                                                             Map<String, Object> oldDataMap) throws IllegalAccessException {

        Map<String, Object> dataMap = new LinkedHashMap<>();
        Map<String, Field> fieldMap = metaInfo.getFieldMap();

        // 确定需要参与计算的字段
        Set<String> includeFields = config.getIncludeFields();
        Set<String> excludeFields = config.getExcludeFields();

        // 排除鉴别码相关字段
        excludeFields.add(config.getContentField());
        excludeFields.add(config.getCodeField());
        if (config.isReturnCheckResult()) {
            excludeFields.add(config.getCheckResultField());
        }
        DataSecurityProperties.EncryptionConfig encryptionConfig = configurationResolver.getEncryptionConfig();
        EncryptionStrategy strategy = getEncryptionStrategy(encryptionConfig);

        for (Map.Entry<String, Field> entry : fieldMap.entrySet()) {
            String fieldName = entry.getKey();
            String columnName = DataSecurityUtils.camelToUnderscore(fieldName);
            Field field = entry.getValue();
            // 排除字段
            if (excludeFields.contains(fieldName)) {
                continue;
            }
            // 如果指定了包含字段，则只包含指定的字段
            if (!includeFields.isEmpty() && !includeFields.contains(fieldName)) {
                continue;
            }
            //获得当前字段插入或更新的策略
            FieldStrategy fieldStrategy = getFieldStrategyByMetaInfo(metaInfo, operateType, field);
            field.setAccessible(true);
            Object value;
            if (plaintextDataMap == null || !plaintextDataMap.containsKey(field)) {
                value = field.get(entity);
                // 如果是加密字段，需要获取解密后的值
                Map<String, ConfigurationResolver.MergedEncryptField> mergedEncryptFieldMap =
                        metaInfo.getMergedEncryptFieldMap();
                if (mergedEncryptFieldMap != null && mergedEncryptFieldMap.containsKey(fieldName)) {
                    if (value != null) {
                        // 临时解密用于生成鉴别码
                        value = strategy.decrypt(value.toString());
                    }
                }
            } else {
                value = plaintextDataMap.get(field);
            }
            //对于插入来说
            //如果是AWAYS 策略，如果值是null，数据库是null
            //如果是NOT_NULL 策略，如果值是null，数据库是null
            //如果是NOT_EMPTY 策略，空字符串，空字符串 参与鉴别码生成 但数据库是 null 鉴别码会鉴别失败  如果是null则不影响
            //如果是NEVER 策略，有值 参与鉴别码生成 但数据库是 null  鉴别码会鉴别失败
            if (SqlOperateType.INSERT.equals(operateType)) {
                if (FieldStrategy.NEVER.equals(fieldStrategy) && value != null) {
                    value = null;
                }
                if (FieldStrategy.NOT_EMPTY.equals(fieldStrategy) && value != null && value.toString().isEmpty()) {
                    value = null;
                }
            }
            //对于更新来说
            //如果是ALWAYS 策略，如果值是null，数据库会被更新为null
            //如果是NOT_NULL 策略，如果值是null，数据库不更新  得以数据库的值为准
            //如果是NOT_EMPTY 策略，空字符串，空字符串  数据库不更新 得以数据库的值为准
            //如果是NEVER 策略，有值 参与鉴别码生成 数据库不更新  鉴别码会鉴别失败
            if (SqlOperateType.UPDATE.equals(operateType)) {
                if (FieldStrategy.NOT_NULL.equals(fieldStrategy) && value == null) {
                    //要以数据库的值为准
                    value = oldDataMap.get(columnName);
                } else if (FieldStrategy.NOT_EMPTY.equals(fieldStrategy) && (value == null || value.toString().isEmpty())) {
                    //要以数据库的值为准
                    value = oldDataMap.get(columnName);
                } else if (FieldStrategy.NEVER.equals(fieldStrategy)) {
                    value = oldDataMap.get(columnName);
                }
            }
            dataMap.put(columnName, value);
        }

        return dataMap;
    }

    private FieldStrategy getFieldStrategyByMetaInfo(EnhancedEntityMetaInfo metaInfo, SqlOperateType operateType, Field field) {
        //获得插入或更新的策略
        FieldStrategy fieldStrategy = FieldStrategy.NOT_NULL;
        if (SqlOperateType.INSERT.equals(operateType)) {
            fieldStrategy = configurationResolver.getGlobalInsertStrategy();
            if (metaInfo.getFieldInsertStrategyMap().containsKey(field)) {
                FieldStrategy tmpStrategy = metaInfo.getFieldInsertStrategyMap().get(field);
                if (!FieldStrategy.DEFAULT.equals(tmpStrategy)) {
                    fieldStrategy = tmpStrategy;
                }
            }
        } else if (SqlOperateType.UPDATE.equals(operateType)) {
            fieldStrategy = configurationResolver.getGlobalUpdateStrategy();
            if (metaInfo.getFieldUpdateStrategyMap().containsKey(field)) {
                FieldStrategy tmpStrategy = metaInfo.getFieldUpdateStrategyMap().get(field);
                if (!FieldStrategy.DEFAULT.equals(tmpStrategy)) {
                    fieldStrategy = tmpStrategy;
                }
            }
        }
        return fieldStrategy;
    }

    private EncryptionStrategy getEncryptionStrategy(DataSecurityProperties.EncryptionConfig config) {
        return strategyManager.getEncryptionStrategy(config.getStrategy());
    }

    private Map<Field, Object> encryptFields(Object entity, EnhancedEntityMetaInfo metaInfo) throws Exception {
        if (!properties.getEncryption().isEnabled()) {
            return null;
        }
        Map<String, Field> fieldMap = metaInfo.getFieldMap();
        Map<String, ConfigurationResolver.MergedEncryptField> mergedEncryptFieldMap =
                metaInfo.getMergedEncryptFieldMap();
        if (mergedEncryptFieldMap == null) {
            return null;
        }
        DataSecurityProperties.EncryptionConfig encryptionConfig = configurationResolver.getEncryptionConfig();
        EncryptionStrategy strategy = getEncryptionStrategy(encryptionConfig);

        Map<Field, Object> plaintextDataMap = new HashMap<>();
        for (Map.Entry<String, ConfigurationResolver.MergedEncryptField> entry :
                mergedEncryptFieldMap.entrySet()) {
            String fieldName = entry.getKey();
            Field field = fieldMap.get(fieldName);
            if (field != null) {
                field.setAccessible(true);
                Object value = field.get(entity);
                plaintextDataMap.put(field, value);
                if (value != null && StringUtils.isNotBlank(value.toString())) {
                    String encrypted = strategy.encrypt(value.toString());
                    field.set(entity, encrypted);
                }
            }
        }
        return plaintextDataMap;
    }

    private void decryptFields(Object entity, EnhancedEntityMetaInfo metaInfo) throws Exception {
        if (!properties.getEncryption().isEnabled()) {
            return;
        }
        Map<String, Field> fieldMap = metaInfo.getFieldMap();
        Map<String, ConfigurationResolver.MergedEncryptField> mergedEncryptFieldMap = metaInfo.getMergedEncryptFieldMap();
        if (mergedEncryptFieldMap == null) {
            return;
        }
        DataSecurityProperties.EncryptionConfig encryptionConfig = configurationResolver.getEncryptionConfig();
        EncryptionStrategy strategy = getEncryptionStrategy(encryptionConfig);
        for (Map.Entry<String, ConfigurationResolver.MergedEncryptField> entry :
                mergedEncryptFieldMap.entrySet()) {
            String fieldName = entry.getKey();
            Field field = fieldMap.get(fieldName);
            if (field != null) {
                field.setAccessible(true);
                Object value = field.get(entity);
                if (value != null) {
                    // 使用指定的加密策略
                    String decrypted = strategy.decrypt(value.toString());
                    field.set(entity, decrypted);
                }
            }
        }
    }

    private Object handleUpdate(Invocation invocation, MappedStatement mappedStatement, Object parameter, String tableName)
            throws Throwable {

        Class<?> tableMapClazz = null;
        if (StringUtils.isNotBlank(tableName)) {
            tableMapClazz = dataSecurityMetadataManager.getClazzByTableName(tableName);
        }

        Object entity = EntityParameterExtractor.extractEntityFromParameter(parameter, mappedStatement, tableMapClazz);
        if (entity == null) {
            return invocation.proceed();
        }

        //这个位置取到的是Mapper中的实体类信息 对于原生SQL来说需要重新处理表名
        Class<?> entityClass = entity.getClass();
        if (tableMapClazz != null) {
            entityClass = tableMapClazz;
        }
        if (entityClass == DataSecurityMetadata.class || entityClass == DataSecurityTask.class) {
            // 跳过对鉴别码元数据的处理，避免死循环
            return invocation.proceed();
        }
        IdentificationCode identificationCode = entityClass.getAnnotation(IdentificationCode.class);
        if (identificationCode == null) {
            // 没有鉴别码注解，直接执行原逻辑
            return invocation.proceed();
        }
        // 获取配置
        ConfigurationResolver.MergedIdentificationCode config = configurationResolver.resolve(entityClass.getAnnotation(IdentificationCode.class));

        if (!config.isEnabled()) {
            return invocation.proceed();
        }

        EnhancedEntityMetaInfo metaInfo = dataSecurityMetadataManager.getEnhancedEntityMetaInfo(entityClass);

        // 使用增强的枚举判断更新类型
        BoundSql boundSql = mappedStatement.getBoundSql(parameter);
        UpdateType updateType = UpdateType.judgeUpdateType(mappedStatement, parameter);
        // 打印日志
//        logUpdateInfo(mappedStatement, updateType, sql, parameter);

        switch (updateType) {
            case INSERT:
                return handleSave(invocation, metaInfo, config, entity);
            case UPDATE_BY_ID:
                handleUpdateById(metaInfo, entity);
                break;
            case UPDATE_WITH_WRAPPER_ONLY:
                handleUpdateWithWrapperOnly(updateType, config, metaInfo);
                break;
            case UPDATE_ENTITY_WITH_QUERY_WRAPPER:
                handleUpdateWithEntityQueryWrapper(updateType, entity, config, metaInfo);
                break;
            case UPDATE_ENTITY_WITH_UPDATE_WRAPPER:
                handleUpdateWithEntityUpdateWrapper(updateType, entity, config, metaInfo);
                break;
            case UPDATE_BY_RAW_SQL:
                handleUpdateByRawSql(boundSql, parameter, entity, config, metaInfo);
                break;
            case UNKNOWN:
            default:
                break;
        }
        return invocation.proceed();
    }

    private Object handleSave(Invocation invocation, EnhancedEntityMetaInfo metaInfo, ConfigurationResolver.MergedIdentificationCode config, Object entity) throws Throwable {
        //处置之前要将鉴别码参数给空
        Field contentField = metaInfo.getIdentificationContentField();
        if (contentField != null) {
            contentField.setAccessible(true);
            contentField.set(entity, null);
        }
        Field codeField = metaInfo.getIdentificationCodeField();
        codeField.setAccessible(true);
        codeField.set(entity, null);

        Object[] args = invocation.getArgs();
        Object data = args[1];

        //保存之前进行加密处置
        //并且暂存加密前的明文数据
        Map<Field, Object> plaintextDataMap = new HashMap<>();
        if (metaInfo.hasEncryptFields()) {
            plaintextDataMap = encryptFields(data, metaInfo);
        }

        //执行原来的插入逻辑 为什么不赋值完成后直接进行更新 因为主键ID可能会参与鉴别码，所以必须执行后拿到鉴别码进行更新
        Object result = invocation.proceed();

        // 处理鉴别码 直接赋值实体字段进行更新
        if (metaInfo.hasIdentificationCode()) {

            Object primaryKeyValue = DataSecurityUtils.getFieldValue(data, DataSecurityUtils.underscoreToCamel(metaInfo.getPrimaryKeyColumn()));
            if (primaryKeyValue != null) {
                // 如果返回了主键ID 说明是单条插入 直接更新鉴别码字段
                IdentificationCodeStrategy.IdentificationCodeInfo codeInfo = getIdentificationCode(data, metaInfo, plaintextDataMap, SqlOperateType.INSERT);
                if (codeInfo == null) {
                    return result;
                }
                //执行更新
                updateIdentificationCodeByWrapper(config, codeInfo, metaInfo, primaryKeyValue);
                //将鉴别码设置到当前对象中  避免后续逻辑使用到鉴别码字段时出现问题
                if (contentField != null) {
                    contentField.setAccessible(true);
                    contentField.set(data, codeInfo.getContent());
                }
                codeField.setAccessible(true);
                codeField.set(data, codeInfo.getCode());
            } else {
                //某些批量更新不会返回主键ID 这时要查询未加鉴别码的记录 生成鉴别码后再更新一次
                QueryWrapper<Map<String, Object>> queryWrapper = new QueryWrapper<>();
                queryWrapper.isNull(config.getCodeField());

                // 查询表中未生成鉴别码的记录
                List<Map<String, Object>> list = dataSecurityMetadataMapper.selectListByWrapper(metaInfo.getTableName(), queryWrapper);

                for (Map<String, Object> record : list) {
                    //循环config 对象获得参与生成鉴别码的字段值 生成鉴别码 更新数据库
                    Map<String, Object> dataMap = new LinkedHashMap<>();
                    Set<String> includeFields = config.getIncludeFields();
                    for (String field : includeFields) {
                        String underscoreField = DataSecurityUtils.camelToUnderscore(field);
                        if (record.containsKey(underscoreField)) {
                            dataMap.put(underscoreField, record.get(underscoreField));
                        }
                    }
                    updateIdentificationCodeByWrapper(config, metaInfo, record.get(metaInfo.getPrimaryKeyColumn()), dataMap);
                }
            }
        }
        return result;
    }

    private void updateIdentificationCodeByWrapper(ConfigurationResolver.MergedIdentificationCode config, EnhancedEntityMetaInfo metaInfo, Object primaryKeyValue, Map<String, Object> dataMap) {
        IdentificationCodeStrategy strategy = strategyManager.getIdentificationCodeStrategy(config.getStrategy());
        IdentificationCodeStrategy.IdentificationCodeInfo codeInfo = strategy.generate(dataMap, metaInfo.getIdentificationCodeAnnotation());
        updateIdentificationCodeByWrapper(config, codeInfo, metaInfo, primaryKeyValue);
    }

    private void updateIdentificationCodeByWrapper(ConfigurationResolver.MergedIdentificationCode config, IdentificationCodeStrategy.IdentificationCodeInfo codeInfo, EnhancedEntityMetaInfo metaInfo, Object primaryKeyValue) {
        if (codeInfo == null) {
            return;
        }
        UpdateWrapper<Map<String, Object>> updateWrapper = new UpdateWrapper<>();
        if (StringUtils.isNotBlank(config.getContentField())) {
            updateWrapper.set(config.getContentField(), codeInfo.getContent());
        }
        if (properties.getIdentification().isContentLog()) {
            log.info("=== 鉴别码原始数据：[{}] {} ", metaInfo.getTableName(), codeInfo.getContent());
        }
        updateWrapper.set(config.getCodeField(), codeInfo.getCode());
        updateWrapper.eq(metaInfo.getPrimaryKeyColumn(), primaryKeyValue);
        // 更新数据库
        dataSecurityMetadataMapper.updateByWrapper(metaInfo.getTableName(), updateWrapper);
    }

    /***
     * 处理根据 ID 更新的情况，直接对实体进行加密和鉴别码生成
     * @param metaInfo 实体元信息
     * @param entity 实体对象
     * @throws Throwable 异常
     */
    private void handleUpdateById(EnhancedEntityMetaInfo metaInfo, Object entity) throws Throwable {
        Map<Field, Object> plaintextDataMap = new HashMap<>();
        if (metaInfo.hasEncryptFields()) {
            plaintextDataMap = encryptFields(entity, metaInfo);
        }
        // 处理鉴别码 直接赋值实体字段进行更新
        if (metaInfo.hasIdentificationCode()) {
            QueryWrapper<Map<String, Object>> queryWrapper = new QueryWrapper<>();
            queryWrapper.eq(metaInfo.getPrimaryKeyColumn(), DataSecurityUtils.getFieldValue(entity, metaInfo.getPrimaryKeyColumn()));
            List<Map<String, Object>> oldDataList = dataSecurityMetadataMapper.selectListByWrapper(metaInfo.getTableName(), queryWrapper);

            setIdentificationCodeToEntity(entity, metaInfo, plaintextDataMap, SqlOperateType.UPDATE, oldDataList == null || oldDataList.isEmpty() ? null : oldDataList.get(0));
        }
    }

    /***
     * 处理使用 UpdateWrapper 进行更新的情况，无法直接获取实体对象，需要解析更新字段来判断是否涉及鉴别码相关字段
     * @param updateType 更新类型
     * @param config 鉴别码配置
     */
    @SuppressWarnings("unchecked")
    private void handleUpdateWithWrapperOnly(UpdateType updateType, ConfigurationResolver.MergedIdentificationCode config, EnhancedEntityMetaInfo metaInfo) {

        UpdateWrapper<?> updateWrapper = (UpdateWrapper<?>) updateType.getWrapper();
        // 解析更新字段
        Map<String, Object> map = UpdateWrapperParser.getUpdateFieldValues(updateWrapper);

        //类配置的加密字段对应的数据列名
        Set<String> columnSet = new HashSet<>();
        if (metaInfo.getEncryptFieldMap() != null && !metaInfo.getEncryptFieldMap().isEmpty()) {
            for (String field : metaInfo.getEncryptFieldMap().keySet()) {
                columnSet.add(DataSecurityUtils.camelToUnderscore(field));
            }
        }
        //如果更新的字段包含了加密字段
        if (hasEncryptionFields(map, columnSet)) {
            // 使用指定的加密策略
            DataSecurityProperties.EncryptionConfig encryptionConfig = configurationResolver.getEncryptionConfig();
            EncryptionStrategy strategy = getEncryptionStrategy(encryptionConfig);
            //如果包含更新字段
            for (String column : columnSet) {
                //如果更新列包含加密字段则加密并重新赋值
                if (map.containsKey(column)) {
                    Object value = map.get(column);
                    if (value != null) {
                        String encrypted = strategy.encrypt(value.toString());
                        updateWrapper.set(column, encrypted);
                    }
                }
            }
        }
        //接下来循环 生成鉴别码并执行更新 只更新鉴别码字段和鉴别码内容字段 避免无限循环
        updateIdentificationCode(config, metaInfo, map, (UpdateWrapper<Map<String, Object>>) updateType.getWrapper());
    }

    /***
     * 处理同时传入实体对象和 QueryWrapper 进行更新的情况，可以获取实体对象，解析实体对象 来判断是否涉及鉴别码相关字段
     * @param updateType 更新类型
     * @param entity 实体对象
     * @param config 鉴别码配置
     */
    @SuppressWarnings("unchecked")
    private void handleUpdateWithEntityQueryWrapper(UpdateType updateType, Object entity, ConfigurationResolver.MergedIdentificationCode config, EnhancedEntityMetaInfo metaInfo) throws Exception {
        if (entity == null) {
            return;
        }
        // 解析更新字段
        Map<String, Object> map = UpdateWrapperParser.getUpdateFieldValues(entity);
        //将需要加密的字段加密后设置到实体中
        setEncryptedToEntity(map, entity, metaInfo, null);
        //生成并更新鉴别码
        updateIdentificationCode(config, metaInfo, map, (Wrapper<Map<String, Object>>) updateType.getWrapper());
    }

    /***
     * 处理加密数据赋值到实体
     * @param map 更新列数据集合
     * @param entity 实体信息
     * @param metaInfo 元数据信息
     * @param updateWrapper 更新Wrapper对象
     * @throws Exception 异常
     */
    private void setEncryptedToEntity(Map<String, Object> map, Object entity, EnhancedEntityMetaInfo metaInfo, UpdateWrapper<?> updateWrapper) throws Exception {
        //类配置的加密字段对应的数据列名
        Set<String> columnSet = new HashSet<>();
        if (metaInfo.getEncryptFieldMap() != null && !metaInfo.getEncryptFieldMap().isEmpty()) {
            for (String field : metaInfo.getEncryptFieldMap().keySet()) {
                columnSet.add(DataSecurityUtils.camelToUnderscore(field));
            }
        }
        //如果更新的字段包含了加密字段
        if (hasEncryptionFields(map, columnSet)) {
            // 使用指定的加密策略
            DataSecurityProperties.EncryptionConfig encryptionConfig = configurationResolver.getEncryptionConfig();
            EncryptionStrategy strategy = getEncryptionStrategy(encryptionConfig);
            //如果包含更新字段
            if (entity != null) {
                Map<String, Field> fieldMap = metaInfo.getFieldMap();
                for (String fieldName : metaInfo.getEncryptFieldMap().keySet()) {
                    String columnName = DataSecurityUtils.camelToUnderscore(fieldName);
                    if (map.containsKey(columnName)) {
                        Object value = map.get(columnName);
                        if (value != null) {
                            Field field = fieldMap.get(fieldName);
                            if (field != null) {
                                String encrypted = strategy.encrypt(value.toString());
                                field.setAccessible(true);
                                field.set(entity, encrypted);
                            }
                        }
                    }
                }
            }
            if (updateWrapper != null) {
                //如果包含更新字段
                for (String column : columnSet) {
                    //如果更新列包含加密字段则加密并重新赋值
                    if (map.containsKey(column)) {
                        Object value = map.get(column);
                        if (value != null) {
                            String encrypted = strategy.encrypt(value.toString());
                            updateWrapper.set(column, encrypted);
                        }
                    }
                }
            }
        }
    }

    /***
     * 处理同时传入实体对象和 UpdateWrapper 进行更新的情况，可以获取实体对象，解析实体对象 来判断是否涉及鉴别码相关字段
     * @param updateType 更新类型
     * @param entity 实体对象
     * @param config 鉴别码配置
     */
    @SuppressWarnings("unchecked")
    private void handleUpdateWithEntityUpdateWrapper(UpdateType updateType, Object entity, ConfigurationResolver.MergedIdentificationCode config, EnhancedEntityMetaInfo metaInfo) throws Exception {
        UpdateWrapper<?> updateWrapper = (UpdateWrapper<?>) updateType.getWrapper();
        // 解析更新字段
        Map<String, Object> map = UpdateWrapperParser.getUpdateFieldValues(updateWrapper, entity);

        //将需要加密的字段加密后设置到实体或wrapper中
        setEncryptedToEntity(map, null, metaInfo, updateWrapper);
        //生成并更新鉴别码

        updateIdentificationCode(config, metaInfo, map, (UpdateWrapper<Map<String, Object>>) updateType.getWrapper());
    }

    /** 处理根据原始 SQL 进行更新的情况，无法直接获取实体对象，需要解析 SQL 和参数来判断是否涉及鉴别码相关字段
     * @param boundSql 原始 BoundSql
     * @param parameter 参数对象
     * @param entity 实体对象（如果能解析出来的话）
     */
    @SuppressWarnings("unchecked")
    private void handleUpdateByRawSql(BoundSql boundSql, Object parameter, Object entity, ConfigurationResolver.MergedIdentificationCode config, EnhancedEntityMetaInfo metaInfo) {
        // 解析 SQL 中的更新字段
        String sql = boundSql.getSql();
        Map<String, Object> parameterMap = new HashMap<>();
        if (parameter instanceof MapperMethod.ParamMap) {
            //获得SQL语句中占位符？的数量
            parameterMap = (Map<String, Object>) parameter;
        } else {

            parameterMap = UpdateWrapperParser.getEntityFieldValues(entity);
        }
        // 1. 提取表名
        String tableName = DataSecurityUtils.extractTableName(sql);
//        log.info("解析到 SQL 中的表名: {}", tableName);
        // 2. 提取SET子句中的字段和值
        ExtractSetResult extractSetResult = DataSecurityUtils.getExtractSetClauseResult(sql, parameterMap, boundSql.getParameterMappings());
//        Map<String, Object> map = DataSecurityUtils.extractSetClause(sql, parameterMap,boundSql.getParameterMappings());
//        log.info("更新字段及值: " + JSON.toJSONString(extractSetResult.getColumnDataMap()));
        // 3. 提取WHERE条件
        Map<String, Object> whereConditionsMap = DataSecurityUtils.extractWhereClause(sql, parameterMap);
//        log.info("解析到 SQL 中的whereConditions: {}", whereConditionsMap);
        // 4. 生成查询语句
        String selectSql = DataSecurityUtils.generateSelectSql(tableName, whereConditionsMap);
//        log.info("解析到 SQL 中的selectSql: {}", selectSql);
        //这里覆盖原来的表名  对于原生SQL来说可能会存在 在Mapper中更新了其他表的情况 这种要覆盖原来的表名，并根据表名获得新的实体类信息
        metaInfo.setTableName(tableName);
        Class<?> entityClass = dataSecurityMetadataManager.getClazzByTableName(tableName);
        if (entityClass != null) {
//            metaInfo.setEntityClass(entityClass);
            metaInfo = dataSecurityMetadataManager.getEnhancedEntityMetaInfo(entityClass);
        } else {
            log.warn("无法根据表名 {} 找到对应的实体类，鉴别码更新可能无法正确执行", tableName);
            return;
        }
//        metaInfo.setPrimaryKeyColumn(DataSecurityUtils.camelToUnderscore(DataSecurityUtils.getPrimaryKeyField(metaInfo.getEntityClass())));
        //类配置的加密字段对应的数据列名
        Set<String> columnSet = new HashSet<>();
        if (metaInfo.getEncryptFieldMap() != null && !metaInfo.getEncryptFieldMap().isEmpty()) {
            for (String field : metaInfo.getEncryptFieldMap().keySet()) {
                columnSet.add(DataSecurityUtils.camelToUnderscore(field));
            }
        }
        //如果更新的字段包含了加密字段
        if (hasEncryptionFields(extractSetResult.getColumnDataMap(), columnSet)) {
            // 使用指定的加密策略
            DataSecurityProperties.EncryptionConfig encryptionConfig = configurationResolver.getEncryptionConfig();
            EncryptionStrategy strategy = getEncryptionStrategy(encryptionConfig);
            //如果包含更新字段
            for (String column : columnSet) {
                //如果更新列包含加密字段则加密并重新赋值
                if (extractSetResult.getColumnDataMap().containsKey(column)) {
                    Object value = extractSetResult.getColumnDataMap().get(column);
                    if (value != null) {
                        String encrypted = strategy.encrypt(value.toString());
                        parameterMap.put(extractSetResult.getColumnMappingParam().get(column), encrypted);
                        parameterMap.put(extractSetResult.getColumnMappingIndexParam().get(column), encrypted);
                    }
                }
            }
        }
        //更新鉴别码信息
        updateIdentificationCode(config, metaInfo, extractSetResult.getColumnDataMap(), selectSql);
    }

    private void updateIdentificationCode(ConfigurationResolver.MergedIdentificationCode config, EnhancedEntityMetaInfo metaInfo, Map<String, Object> updateDataMap, Wrapper<Map<String, Object>> wrapper) {
        updateIdentificationCode(config, metaInfo, updateDataMap, wrapper, null);
    }

    private void updateIdentificationCode(ConfigurationResolver.MergedIdentificationCode config, EnhancedEntityMetaInfo metaInfo, Map<String, Object> updateDataMap, String selectSql) {
        updateIdentificationCode(config, metaInfo, updateDataMap, null, selectSql);
    }

    private void updateIdentificationCode(ConfigurationResolver.MergedIdentificationCode config, EnhancedEntityMetaInfo metaInfo, Map<String, Object> updateDataMap, Wrapper<?> wrapper, String selectSql) {
        if (updateDataMap.isEmpty()) {
            return;
        }
        // 检查是否有涉及鉴别码生成的字段
        if (!hasIdentificationFields(updateDataMap, config.getIncludeFields())) {
            log.debug("数据安全插件：实体类 {} 数据表 {} 未更新鉴别码相关的字段", metaInfo.getEntityClass().getSimpleName(), metaInfo.getTableName());
            return;
        }
        List<Map<String, Object>> list;
        if (StringUtils.isNotBlank(selectSql)) {
            list = dataSecurityMetadataMapper.selectListBySql(selectSql);
        } else if (wrapper != null) {
            list = dataSecurityMetadataMapper.selectListByWrapper(metaInfo.getTableName(), wrapper);
        } else {
            log.warn("数据安全插件：实体类 {} 数据表 {} 无法执行更新，缺少查询条件", metaInfo.getEntityClass().getSimpleName(), metaInfo.getTableName());
            return;
        }
        if (list == null || list.isEmpty()) {
            log.debug("数据安全插件：实体类 {} 数据表 {} 未查询到需要更新的数据", metaInfo.getEntityClass().getSimpleName(), metaInfo.getTableName());
            return;
        }
        //接下来循环 生成鉴别码并执行更新 只更新鉴别码字段和鉴别码内容字段 避免无限循环
        for (Map<String, Object> record : list) {
            //循环config 对象获得参与生成鉴别码的字段值 生成鉴别码 更新数据库
            Map<String, Object> dataMap = new LinkedHashMap<>();
            Set<String> includeFields = config.getIncludeFields();
            for (String field : includeFields) {
                String underscoreField = DataSecurityUtils.camelToUnderscore(field);
                if (updateDataMap.containsKey(underscoreField)) {
                    dataMap.put(underscoreField, updateDataMap.get(underscoreField));
                } else if (record.containsKey(underscoreField)) {
                    dataMap.put(underscoreField, record.get(underscoreField));
                }
            }
            // 使用指定的策略
            IdentificationCodeStrategy strategy = strategyManager.getIdentificationCodeStrategy(config.getStrategy());
            IdentificationCodeStrategy.IdentificationCodeInfo codeInfo = strategy.generate(dataMap, metaInfo.getIdentificationCodeAnnotation());
            // 构建更新字段
            UpdateWrapper<Map<String, Object>> updateWrapper = new UpdateWrapper<>();
            if (StringUtils.isNotBlank(config.getContentField())) {
                updateWrapper.set(config.getContentField(), codeInfo.getContent());
            }
            if (properties.getIdentification().isContentLog()) {
                log.info("=== 鉴别码原始数据：[{}] {} ", metaInfo.getTableName(), codeInfo.getContent());
            }
            updateWrapper.set(config.getCodeField(), codeInfo.getCode());
            updateWrapper.eq(metaInfo.getPrimaryKeyColumn(), record.get(metaInfo.getPrimaryKeyColumn()));
            // 更新数据库
            dataSecurityMetadataMapper.updateByWrapper(metaInfo.getTableName(), updateWrapper);
        }
    }


    /***
     * 检查更新字段中是否包含鉴别码生成相关的字段
     * @param map 更新字段及其值的 Map
     * @param includeFields 鉴别码生成相关的字段集合
     * @return 如果包含则返回 true，否则返回 false
     */
    private boolean hasIdentificationFields(Map<String, Object> map, Set<String> includeFields) {
        if (map == null || map.isEmpty() || includeFields.isEmpty()) {
            return false;
        }

        for (String columnName : map.keySet()) {
            if (includeFields.contains(columnName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查更新字段中是否包含加密相关的字段
     * @param map 更新字段及其值的 Map
     * @param includeFields 鉴别码生成相关的字段集合
     * @return 如果包含则返回 true，否则返回 false
     */
    private boolean hasEncryptionFields(Map<String, Object> map, Set<String> includeFields) {
        return hasEncryptionFields(map, includeFields, false);
    }

    /**
     * 检查更新字段中是否包含加密相关的字段
     * @param map 更新字段及其值的 Map
     * @param includeFields 鉴别码生成相关的字段集合
     * @return 如果包含则返回 true，否则返回 false
     */
    private boolean hasEncryptionFields(Map<String, Object> map, Set<String> includeFields, boolean isCamel) {
        if (map == null || map.isEmpty() || includeFields.isEmpty()) {
            return false;
        }
        for (String columnName : map.keySet()) {
            if (includeFields.contains(isCamel ? DataSecurityUtils.underscoreToCamel(columnName) : columnName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 记录更新信息
     */
    private void logUpdateInfo(MappedStatement mappedStatement, UpdateType updateType, String sql, Object parameter) {
        String methodId = mappedStatement.getId();
        log.info("更新操作检测 - 方法: {}, 类型: {}, 描述: {}, SQL: {}",
                methodId, updateType, updateType.getDescription(), sql);
    }

    private Object handleQuery(Invocation invocation, String tableName)
            throws Throwable {
        if (tableName != null && (tableName.equalsIgnoreCase("data_security_metadata")
                || tableName.equalsIgnoreCase("data_security_task"))) {
            // 元数据数据表，继续执行原逻辑
            return invocation.proceed();
        }
        Object result = invocation.proceed();
        if (result == null) {
            return result;
        }
        if (result instanceof List) {
            List<?> resultList = (List<?>) result;
            List<Object> processedList = new ArrayList<>();
            for (Object item : resultList) {
                processedList.add(processQueryResult(item));
            }
            return processedList;
        } else {
            return processQueryResult(result);
        }
    }

    private Object processQueryResult(Object result) throws Exception {
        if (result == null) {
            return null;
        }

        Class<?> entityClass = result.getClass();
        EnhancedEntityMetaInfo metaInfo = dataSecurityMetadataManager.getEnhancedEntityMetaInfo(entityClass);

        // 解密字段
        if (metaInfo.hasEncryptFields()) {
            decryptFields(result, metaInfo);
        }

        // 验证鉴别码
        if (metaInfo.hasIdentificationCode()) {
            boolean isValid = verifyIdentificationCode(result, metaInfo);

            // 设置校验结果
            if (metaInfo.getCheckResultField() != null) {
                Field checkResultField = metaInfo.getCheckResultField();
                checkResultField.setAccessible(true);

                // 根据字段类型设置值
                Class<?> fieldType = checkResultField.getType();
                if (fieldType == boolean.class || fieldType == Boolean.class) {
                    checkResultField.set(result, isValid);
                } else if (fieldType == Integer.class || fieldType == int.class) {
                    checkResultField.set(result, isValid ? 1 : 0);
                } else if (fieldType == String.class) {
                    checkResultField.set(result, isValid ? "VALID" : "INVALID");
                }
            }
        }

        return result;
    }

    private boolean verifyIdentificationCode(Object entity, EntityMetaInfo metaInfo) throws Exception {
        IdentificationCode annotation = metaInfo.getIdentificationCodeAnnotation();
//        Field contentField = metaInfo.getIdentificationContentField();
        Field codeField = metaInfo.getIdentificationCodeField();

        if (codeField == null) {
            return false;
        }

        // 获取存储的鉴别码
//        contentField.setAccessible(true);
        codeField.setAccessible(true);
//        String storedContent = (String) contentField.get(entity);
        String storedCode = (String) codeField.get(entity);

        if (StringUtils.isBlank(storedCode)) {
            return false;
        }

        // 收集当前数据
        Map<String, Object> dataMap = collectDataForIdentification(entity, metaInfo, annotation);

        // 使用自定义鉴别码策略验证
        IdentificationCodeStrategy strategy = strategyManager.getIdentificationCodeStrategy(properties.getIdentification().getStrategy());
        return strategy.verify(storedCode, dataMap, annotation);
    }

    private Map<String, Object> collectDataForIdentification(Object entity,
                                                             EntityMetaInfo metaInfo,
                                                             IdentificationCode annotation)
            throws IllegalAccessException {

        Map<String, Object> dataMap = new LinkedHashMap<>();
        Map<String, Field> fieldMap = metaInfo.getFieldMap();

        // 确定需要参与计算的字段
        Set<String> includeFields = new HashSet<>(Arrays.asList(annotation.includeFields()));
        Set<String> excludeFields = new HashSet<>(Arrays.asList(annotation.excludeFields()));

        // 排除鉴别码相关字段
        excludeFields.add(annotation.contentField());
        excludeFields.add(annotation.codeField());
        if (annotation.returnCheckResult()) {
            excludeFields.add(annotation.checkResultField());
        }

        for (Map.Entry<String, Field> entry : fieldMap.entrySet()) {
            String fieldName = entry.getKey();
            Field field = entry.getValue();

            // 排除字段
            if (excludeFields.contains(fieldName)) {
                continue;
            }

            // 如果指定了包含字段，则只包含指定的字段
            if (!includeFields.isEmpty() && !includeFields.contains(fieldName)) {
                continue;
            }

            field.setAccessible(true);
            Object value = field.get(entity);

            // 如果是加密字段，需要获取解密后的值
            if (metaInfo.getEncryptFieldMap().containsKey(fieldName)) {
                EncryptField encryptAnnotation = metaInfo.getEncryptFieldMap().get(fieldName);
                if (value != null) {
                    // 临时解密用于生成鉴别码
                    EncryptionStrategy strategy = strategyManager.getEncryptionStrategy(properties.getEncryption().getStrategy());
                    value = strategy.decrypt(value.toString());
                }
            }
            dataMap.put(DataSecurityUtils.camelToUnderscore(fieldName), value);
        }

        return dataMap;
    }

    private List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        while (clazz != null && clazz != Object.class) {
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            clazz = clazz.getSuperclass();
        }
        return fields;
    }

    private Object extractEntityFromParameter(Object parameter, MappedStatement mappedStatement) {
        // 简化实现，实际应根据参数类型提取
        if (parameter != null &&
                !(parameter instanceof Map) &&
                !(parameter instanceof QueryWrapper)) {
            return parameter;
        }
        return null;
    }

    @Override
    public Object plugin(Object target) {
        if (target instanceof Executor) {
            return Plugin.wrap(target, this);
        }
        return target;
    }

    @Override
    public void setProperties(Properties properties) {
        // 配置属性
    }


    /**
     * 实体元信息
     */
    @Setter
    @Getter
    public static class EntityMetaInfo {
        // getters and setters
        private Class<?> entityClass;
        private Map<String, Field> fieldMap;
        private Map<Field, FieldStrategy> fieldUpdateStrategyMap;
        private Map<Field, FieldStrategy> fieldInsertStrategyMap;
        private Map<String, EncryptField> encryptFieldMap;
        private IdentificationCode identificationCodeAnnotation;
        private Field identificationContentField;
        private Field identificationCodeField;
        private Field checkResultField;
        private String tableName;
        private String primaryKeyColumn;

        public boolean hasEncryptFields() {
            return encryptFieldMap != null && !encryptFieldMap.isEmpty();
        }

        public boolean hasIdentificationCode() {
            return identificationCodeAnnotation != null;
        }

    }
}
