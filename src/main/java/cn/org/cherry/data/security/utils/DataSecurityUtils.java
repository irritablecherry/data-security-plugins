package cn.org.cherry.data.security.utils;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.info.ExtractSetResult;
import cn.org.cherry.data.security.info.UpdateInfo;
import com.alibaba.fastjson.JSON;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.core.conditions.SharedString;
import com.baomidou.mybatisplus.core.conditions.segments.MergeSegments;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.core.metadata.TableFieldInfo;
import com.baomidou.mybatisplus.core.metadata.TableInfo;
import com.baomidou.mybatisplus.core.metadata.TableInfoHelper;
import com.baomidou.mybatisplus.core.toolkit.Constants;
import com.baomidou.mybatisplus.core.toolkit.ReflectionKit;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import org.apache.ibatis.binding.MapperMethod;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.SystemMetaObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class DataSecurityUtils {

    // 缓存实体类的鉴别码字段配置
    private static final Map<Class<?>, ConfigurationResolver.MergedIdentificationCode> IDENTIFICATION_CONFIG_CACHE =
            new ConcurrentHashMap<>();

    // 缓存 Lambda 表达式对应的属性名
    private static final Map<String, String> LAMBDA_PROPERTY_CACHE = new ConcurrentHashMap<>();
    private static final Logger log = LoggerFactory.getLogger(DataSecurityUtils.class);

    /**
     * 下划线转驼峰
     */
    public static String underscoreToCamel(String str) {
        if (StringUtils.isBlank(str)) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        boolean nextUpper = false;
        for (char c : str.toCharArray()) {
            if (c == '_') {
                nextUpper = true;
            } else {
                if (nextUpper) {
                    result.append(Character.toUpperCase(c));
                    nextUpper = false;
                } else {
                    result.append(c);
                }
            }
        }
        return result.toString();
    }

    /**
     * 驼峰转下划线
     */
    public static String camelToUnderscore(String str) {
        if (StringUtils.isBlank(str)) {
            return "";
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
     * 解析 UpdateWrapper 中的更新字段
     */
    public static List<String> parseUpdateFields(UpdateWrapper<?> updateWrapper, Class<?> entityClass) {
        List<String> updateFields = new ArrayList<>();

        if (updateWrapper == null) {
            return updateFields;
        }
//        UpdateInfo updateInfo = UpdateWrapperParser.parseUpdateWrapper(updateWrapper);
        Map<String, Object> map = UpdateWrapperParser.getUpdateFieldValues(updateWrapper);
        try {
            // 方法1：从 sqlSet 字段解析
            updateFields.addAll(parseUpdateFieldsFromSqlSet(updateWrapper, entityClass));

            // 方法2：从 lambdaUpdateWrapper 解析
            updateFields.addAll(parseUpdateFieldsFromLambda(updateWrapper, entityClass));

            // 方法3：从 entity 字段解析
            updateFields.addAll(parseUpdateFieldsFromEntity(updateWrapper, entityClass));

        } catch (Exception e) {
            // 忽略解析异常
        }

        return updateFields.stream()
                .filter(StringUtils::isNotBlank)
                .distinct()
                .collect(Collectors.toList());
    }

    /**
     * 从 sqlSet 字段解析更新字段
     */
    private static List<String> parseUpdateFieldsFromSqlSet(UpdateWrapper<?> updateWrapper, Class<?> entityClass) {
        List<String> fields = new ArrayList<>();

        try {
            // 获取 sqlSet 字符串
            String sqlSet = getSqlSet(updateWrapper);
            if (StringUtils.isBlank(sqlSet)) {
                return fields;
            }

            // 解析 SQL SET 语句
            // 示例: "nickname = ?, age = ?"
            String[] setItems = sqlSet.split(",");

            for (String setItem : setItems) {
                if (setItem.contains("=")) {
                    String columnPart = setItem.substring(0, setItem.indexOf("=")).trim();

                    // 去掉表别名、反引号等
                    columnPart = columnPart.replace("`", "");

                    // 如果包含点号，取点号后面的部分
                    if (columnPart.contains(".")) {
                        columnPart = columnPart.substring(columnPart.lastIndexOf(".") + 1);
                    }

                    // 转换为实体字段名
                    String fieldName = convertColumnToField(columnPart, entityClass);
                    if (fieldName != null) {
                        fields.add(fieldName);
                    }
                }
            }

        } catch (Exception e) {
            // 忽略解析异常
        }

        return fields;
    }

    /**
     * 获取 UpdateWrapper 的 sqlSet
     */
    private static String getSqlSet(UpdateWrapper<?> updateWrapper) {
        try {
            Field sqlSetField = ReflectionUtils.findField(updateWrapper.getClass(), "sqlSet");
            if (sqlSetField != null) {
                sqlSetField.setAccessible(true);
                SharedString sqlSet = (SharedString) sqlSetField.get(updateWrapper);
                return sqlSet != null ? sqlSet.getStringValue() : null;
            }
        } catch (Exception e) {
            log.error("解析 UpdateWrapper 的 sqlSet 失败", e);
            // 忽略异常
        }
        return null;
    }

    /**
     * 从 Lambda 表达式解析更新字段
     */
    private static List<String> parseUpdateFieldsFromLambda(UpdateWrapper<?> updateWrapper, Class<?> entityClass) {
        List<String> fields = new ArrayList<>();

        try {
            // 获取 paramNameValuePairs
            Field paramNameValuePairsField = ReflectionUtils.findField(
                    updateWrapper.getClass(), "paramNameValuePairs");

            if (paramNameValuePairsField == null) {
                return fields;
            }

            paramNameValuePairsField.setAccessible(true);
            Map<String, Object> paramMap = (Map<String, Object>) paramNameValuePairsField.get(updateWrapper);

            if (CollectionUtils.isEmpty(paramMap)) {
                return fields;
            }

            // 分析参数名称，识别 Lambda 表达式设置的字段
            for (String paramName : paramMap.keySet()) {
                if (paramName.startsWith(Constants.WRAPPER_PARAM + ".paramNameValuePairs")) {
                    // 这是 Lambda 表达式设置的参数
                    // 示例: "ew.paramNameValuePairs.MPGENVAL1"
                    continue;
                }

                // 尝试解析 Lambda 表达式
                if (paramName.contains("lambda$")) {
                    // 这是一个 Lambda 表达式
                    String fieldName = extractFieldNameFromLambdaParam(paramName, entityClass);
                    if (fieldName != null) {
                        fields.add(fieldName);
                    }
                }
            }

        } catch (Exception e) {
            // 忽略异常
        }

        return fields;
    }

    /**
     * 从 entity 字段解析更新字段
     */
    private static List<String> parseUpdateFieldsFromEntity(UpdateWrapper<?> updateWrapper, Class<?> entityClass) {
        List<String> fields = new ArrayList<>();

        try {
            // 获取 entity
            Method getEntityMethod = updateWrapper.getClass().getMethod("getEntity");
            Object entity = getEntityMethod.invoke(updateWrapper);

            if (entity == null) {
                return fields;
            }

            // 如果 entity 是 Map，解析 Map 的键
            if (entity instanceof Map) {
                Map<?, ?> entityMap = (Map<?, ?>) entity;
                for (Object key : entityMap.keySet()) {
                    if (key instanceof String) {
                        String fieldName = (String) key;
                        // 验证字段是否存在于实体类中
                        if (hasField(entityClass, fieldName)) {
                            fields.add(fieldName);
                        }
                    }
                }
            } else if (entity.getClass() == entityClass) {
                // 实体对象，获取所有非空字段
                MetaObject metaObject = SystemMetaObject.forObject(entity);
                String[] getterNames = metaObject.getGetterNames();

                for (String getterName : getterNames) {
                    // 去掉 get/is 前缀，获取字段名
                    String fieldName = getterName.replaceFirst("^(get|is)", "");
                    fieldName = Character.toLowerCase(fieldName.charAt(0)) + fieldName.substring(1);

                    // 获取字段值
                    Object value = metaObject.getValue(getterName);
                    if (value != null && hasField(entityClass, fieldName)) {
                        fields.add(fieldName);
                    }
                }
            }

        } catch (Exception e) {
            // 忽略异常
        }

        return fields;
    }

    /**
     * 从 Lambda 参数名提取字段名
     */
    private static String extractFieldNameFromLambdaParam(String paramName, Class<?> entityClass) {
        try {
            // 示例: "ew.paramNameValuePairs.MPGENVAL1"
            // 或: "nickname"

            // 如果已经缓存了，直接返回
            String cachedField = LAMBDA_PROPERTY_CACHE.get(paramName);
            if (cachedField != null) {
                return cachedField;
            }

            // 尝试解析 Lambda 表达式
            if (paramName.contains("$Lambda$")) {
                // 这是 Lambda 表达式，需要特殊处理
                // 这里简化处理，实际需要解析 Lambda 表达式
                return null;
            }

            // 尝试直接作为字段名
            if (hasField(entityClass, paramName)) {
                LAMBDA_PROPERTY_CACHE.put(paramName, paramName);
                return paramName;
            }

        } catch (Exception e) {
            // 忽略异常
        }

        return null;
    }

    /**
     * 检查实体类是否有指定字段
     */
    private static boolean hasField(Class<?> clazz, String fieldName) {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            return field != null;
        } catch (NoSuchFieldException e) {
            // 检查父类
            Class<?> superClass = clazz.getSuperclass();
            if (superClass != null && superClass != Object.class) {
                return hasField(superClass, fieldName);
            }
            return false;
        }
    }

    /**
     * 将数据库列名转换为实体字段名
     */
    private static String convertColumnToField(String columnName, Class<?> entityClass) {
        if (StringUtils.isBlank(columnName) || entityClass == null) {
            return null;
        }

        // 获取 TableInfo
        TableInfo tableInfo = TableInfoHelper.getTableInfo(entityClass);
        if (tableInfo == null) {
            return null;
        }

        // 遍历字段，查找匹配的列
        for (TableFieldInfo fieldInfo : tableInfo.getFieldList()) {
            if (columnName.equalsIgnoreCase(fieldInfo.getColumn())) {
                return fieldInfo.getProperty();
            }
        }

        // 尝试下划线转驼峰
        return underscoreToCamel(columnName);
    }

    /**
     * 检查是否有涉及鉴别码生成的字段被更新
     */
    private static boolean hasIdentificationFieldsUpdated(List<String> updateFields,
                                                          ConfigurationResolver.MergedIdentificationCode config) {
        if (CollectionUtils.isEmpty(updateFields) || config.getIncludeFields() == null) {
            return false;
        }

        // 检查更新的字段是否在 includeFields 中
        for (String updateField : updateFields) {
            if (config.getIncludeFields().contains(updateField)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 重新生成鉴别码并追加到 UpdateWrapper
     */
    private static void regenerateAndAppendIdentificationCode(UpdateWrapper<?> updateWrapper,
                                                              Class<?> entityClass,
                                                              Object entity,
                                                              ConfigurationResolver.MergedIdentificationCode config) {

        try {
            // 获取主键值
            Object id = getEntityId(updateWrapper, entityClass);
            if (id == null) {
                // 如果没有明确的主键，无法重新生成鉴别码
                return;
            }

            // 这里需要从数据库查询原始实体，然后应用更新字段，重新生成鉴别码
            // 由于这个过程比较复杂，这里简化处理：
            // 1. 设置鉴别码字段为占位符，表示需要重新生成
            // 2. 实际生成逻辑在业务层或数据库触发器中实现

            // 获取表信息
            TableInfo tableInfo = TableInfoHelper.getTableInfo(entityClass);
            if (tableInfo == null) {
                return;
            }

            // 查找鉴别码字段对应的列名
            String contentColumn = getColumnName(tableInfo, config.getContentField());
            String codeColumn = getColumnName(tableInfo, config.getCodeField());

            if (contentColumn != null && codeColumn != null) {
                // 设置鉴别码字段为需要重新生成的标记
                // 这里可以设置一个特殊值，或者调用特定的生成函数
                updateWrapper.set(contentColumn, "TO_BE_REGENERATED");
                updateWrapper.set(codeColumn, "TO_BE_REGENERATED");

                // 或者抛出自定义异常，提示需要处理鉴别码
                // throw new IdentificationCodeRegenerationRequiredException("需要重新生成鉴别码");
            }

        } catch (Exception e) {
            // 忽略异常
        }
    }

    /**
     * 获取实体主键值
     */
    private static Object getEntityId(UpdateWrapper<?> updateWrapper, Class<?> entityClass) {
        try {
            // 解析 UpdateWrapper 的条件，查找主键条件
            String whereSql = getWhereSql(updateWrapper);
            if (StringUtils.isBlank(whereSql)) {
                return null;
            }

            // 解析 WHERE 条件，查找主键条件
            // 这里简化处理，实际需要解析 SQL
            TableInfo tableInfo = TableInfoHelper.getTableInfo(entityClass);
            if (tableInfo == null) {
                return null;
            }

            String keyColumn = tableInfo.getKeyColumn();
            if (keyColumn == null) {
                return null;
            }

            // 在 WHERE 条件中查找主键条件
            // 示例: "id = 1"
            Pattern pattern = Pattern.compile(keyColumn + "\\s*=\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(whereSql);

            if (matcher.find()) {
                return Long.parseLong(matcher.group(1));
            }

        } catch (Exception e) {
            // 忽略异常
        }

        return null;
    }

    /**
     * 获取 WHERE 条件 SQL
     */
    private static String getWhereSql(UpdateWrapper<?> updateWrapper) {
        try {
            Field expressionField = ReflectionUtils.findField(updateWrapper.getClass(), "expression");
            if (expressionField != null) {
                expressionField.setAccessible(true);
                MergeSegments expression = (MergeSegments) expressionField.get(updateWrapper);

                if (expression != null) {
                    Field sqlSegmentField = ReflectionUtils.findField(expression.getClass(), "sqlSegment");
                    if (sqlSegmentField != null) {
                        sqlSegmentField.setAccessible(true);
                        SharedString sqlSegment = (SharedString) sqlSegmentField.get(expression);
                        return sqlSegment != null ? sqlSegment.getStringValue() : null;
                    }
                }
            }
        } catch (Exception e) {
            // 忽略异常
        }
        return null;
    }

    /**
     * 获取字段对应的列名
     */
    private static String getColumnName(TableInfo tableInfo, String fieldName) {
        if (tableInfo == null || StringUtils.isBlank(fieldName)) {
            return null;
        }

        for (TableFieldInfo fieldInfo : tableInfo.getFieldList()) {
            if (fieldName.equals(fieldInfo.getProperty())) {
                return fieldInfo.getColumn();
            }
        }

        return null;
    }

    /**
     * 获取鉴别码配置
     */
//    private static IdentificationFieldConfig getIdentificationConfig(Class<?> entityClass,
//                                                                     IdentificationCode annotation) {
//        return IDENTIFICATION_CONFIG_CACHE.computeIfAbsent(entityClass, clazz -> {
//            IdentificationFieldConfig config = new IdentificationFieldConfig();
//
//            if (annotation == null) {
//                config.enabled = false;
//                return config;
//            }
//
//            ConfigurationResolver.MergedIdentificationCode mergedConfig =
//                    configurationResolver.resolve(annotation);
//
//            if (!mergedConfig.isEnabled()) {
//                config.enabled = false;
//                return config;
//            }
//
//            config.enabled = true;
//            config.contentField = mergedConfig.getContentField();
//            config.codeField = mergedConfig.getCodeField();
//            config.includeFields = new HashSet<>(mergedConfig.getIncludeFields());
//            config.excludeFields = new HashSet<>(mergedConfig.getExcludeFields());
//
//            return config;
//        });
//    }

    /**
     * 获取实体类
     */
    private static Class<?> getEntityClass(MappedStatement mappedStatement) {
        try {
            String mapperClassName = getMapperClassName(mappedStatement);
            if (mapperClassName == null) {
                return null;
            }

            Class<?> mapperClass = Class.forName(mapperClassName);

            // 获取实体类（通过泛型）
            Class<?> entityClass = ReflectionKit.getSuperClassGenericType(mapperClass,
                    com.baomidou.mybatisplus.core.mapper.BaseMapper.class, 0);

            if (entityClass != null && !Object.class.equals(entityClass)) {
                return entityClass;
            }

        } catch (Exception e) {
            // 忽略异常
        }

        return null;
    }

    /**
     * 获取 Mapper 类名
     */
    private static String getMapperClassName(MappedStatement mappedStatement) {
        if (mappedStatement == null) {
            return null;
        }

        String statementId = mappedStatement.getId();
        if (StringUtils.isBlank(statementId)) {
            return null;
        }

        int lastDotIndex = statementId.lastIndexOf('.');
        if (lastDotIndex > 0) {
            return statementId.substring(0, lastDotIndex);
        }

        return null;
    }

    /**
     * 增强版：避免匹配字符串或注释中的问号
     * 例如：UPDATE users SET name = 'John?' WHERE id = ?
     * 字符串中的问号不应该被计为占位符
     */
    public static int countPlaceholdersEnhanced(String sql) {
        if (sql == null || sql.trim().isEmpty()) {
            return 0;
        }

        // 移除单行和多行注释
        String cleanedSql = removeComments(sql);

        // 移除字符串常量（防止字符串中的问号被误识别为占位符）
        cleanedSql = removeStringLiterals(cleanedSql);

        // 统计问号数量
        int count = 0;
        for (int i = 0; i < cleanedSql.length(); i++) {
            if (cleanedSql.charAt(i) == '?') {
                count++;
            }
        }

        return count;
    }

    /**
     * 移除SQL注释
     */
    private static String removeComments(String sql) {
        if (sql == null) {
            return "";
        }

        // 移除多行注释 /* ... */
        String noMultiLineComments = sql.replaceAll("/\\*.*?\\*/", "");

        // 移除单行注释 --
        String noSingleLineComments = noMultiLineComments.replaceAll("--[^\\n]*", "");

        return noSingleLineComments;
    }

    /**
     * 移除字符串常量，用占位符替换
     */
    private static String removeStringLiterals(String sql) {
        if (sql == null) {
            return "";
        }

        StringBuilder result = new StringBuilder();
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < sql.length(); i++) {
            char c = sql.charAt(i);

            if (escaped) {
                escaped = false;
                if (!inString) {
                    result.append(c);
                }
            } else if (c == '\\') {
                escaped = true;
                if (!inString) {
                    result.append(c);
                }
            } else if (c == '\'' || c == '"') {
                inString = !inString;
                // 不将字符串内容添加到结果中
            } else if (!inString) {
                result.append(c);
            }
            // 如果在字符串中，跳过该字符
        }

        return result.toString();
    }

    /**
     * 提取表名
     */
    public static String extractTableName(String sql) {
        // 正则匹配 UPDATE 表名 SET
        try {
            Pattern pattern = Pattern.compile("UPDATE\\s+([\\w.]+)\\s+SET", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(sql.toUpperCase());

            if (matcher.find()) {
                // 获取原SQL中的表名（保持原样，不转大写）
                String upperSql = sql.toUpperCase();
                int start = matcher.start(1);
                int end = matcher.end(1);
                return sql.substring(start, end).trim();
            }
        } catch (Exception ex) {
            // 忽略异常
            log.error("提取表名失败", ex);
        }
        return null;
    }

    /**
     * 提取SET子句
     */
    public static Map<String, Object> extractSetClause(String sql, Map<String, Object> paramMap, List<ParameterMapping> parameterMappingList) {
        Map<String, Object> setFields = new LinkedHashMap<>();

        // 找到SET和WHERE之间的部分
        String upperSql = sql.toUpperCase();
        int setIndex = upperSql.indexOf("SET");
        int whereIndex = upperSql.indexOf("WHERE");

        if (setIndex == -1) {
            throw new IllegalArgumentException("SQL中没有SET子句: " + sql);
        }

        // 提取SET子句部分
        String setClause;
        if (whereIndex == -1) {
            // 没有WHERE子句
            setClause = sql.substring(setIndex + 3).trim();
        } else {
            setClause = sql.substring(setIndex + 3, whereIndex).trim();
        }

        // 解析SET子句中的字段赋值
        // 格式: field1 = ?, field2 = value2, field3 = ?
        String[] assignments = setClause.split(",");

        int index = 0;
        for (String assignment : assignments) {
            assignment = assignment.trim();
            if (assignment.isEmpty()) continue;

            // 按等号分割字段名和值
            String[] parts = assignment.split("=", 2);
            if (parts.length != 2) {
                continue; // 跳过格式错误的部分
            }
            String fieldName = parts[0].trim();
            String valueStr = parts[1].trim();

            // 处理值
            Object value = null;

            if (valueStr.equals("?")) {
                log.info("index:" + index);
                String property = parameterMappingList.get(index).getProperty();
                log.info("property:" + property);
                // 预处理参数，从Map中获取
                value = paramMap.get(property);
                if (value == null) {
                    // 如果按字段名找不到，尝试按占位符顺序获取
                    // 这里需要记录占位符位置，简化处理：如果paramMap的size=1，直接取第一个
                    if (paramMap.size() == 1) {
                        value = paramMap.values().iterator().next();
                    }
                }
                index++;
            } else {
                // 字面值
                value = parseValue(valueStr);
            }

            setFields.put(fieldName, value);
        }

        return setFields;
    }

    public static ExtractSetResult getExtractSetClauseResult(String sql, Map<String, Object> paramMap, List<ParameterMapping> parameterMappingList) {
        Map<String, Object> setFields = new LinkedHashMap<>();
        Map<String, String> columnMappingParam = new LinkedHashMap<>();
        Map<String, String> columnMappingIndexParam = new LinkedHashMap<>();

        // 找到SET和WHERE之间的部分
        String upperSql = sql.toUpperCase();
        int setIndex = upperSql.indexOf("SET");
        int whereIndex = upperSql.indexOf("WHERE");

        if (setIndex == -1) {
            throw new IllegalArgumentException("SQL中没有SET子句: " + sql);
        }

        // 提取SET子句部分
        String setClause;
        if (whereIndex == -1) {
            // 没有WHERE子句
            setClause = sql.substring(setIndex + 3).trim();
        } else {
            setClause = sql.substring(setIndex + 3, whereIndex).trim();
        }

        // 解析SET子句中的字段赋值
        // 格式: field1 = ?, field2 = value2, field3 = ?
        String[] assignments = setClause.split(",");

        int index = 0;
        for (String assignment : assignments) {
            assignment = assignment.trim();
            if (assignment.isEmpty()) continue;

            // 按等号分割字段名和值
            String[] parts = assignment.split("=", 2);
            if (parts.length != 2) {
                continue; // 跳过格式错误的部分
            }
            String columnName = parts[0].trim();
            String valueStr = parts[1].trim();

            // 处理值
            Object value = null;

            if (valueStr.equals("?")) {
//                log.info("index:" + index);
                String property = parameterMappingList.get(index).getProperty();
//                log.info("property:" + property);
                columnMappingParam.put(columnName, property);
                columnMappingIndexParam.put(columnName, "param" + (index + 1));
                // 预处理参数，从Map中获取
                value = paramMap.get(property);
                if (value == null) {
                    // 如果按字段名找不到，尝试按占位符顺序获取
                    // 这里需要记录占位符位置，简化处理：如果paramMap的size=1，直接取第一个
                    if (paramMap.size() == 1) {
                        value = paramMap.values().iterator().next();
                    }
                }
                index++;
            } else {
                // 字面值
                value = parseValue(valueStr);
            }
            setFields.put(columnName, value);
        }

        return new ExtractSetResult(setFields, columnMappingParam, columnMappingIndexParam);
    }

    /**
     * 解析值（处理字符串、数字、null等）
     */
    private static Object parseValue(String valueStr) {
        valueStr = valueStr.trim();

        // 处理NULL
        if (valueStr.equalsIgnoreCase("NULL")) {
            return null;
        }

        // 处理字符串（单引号或双引号包围）
        if ((valueStr.startsWith("'") && valueStr.endsWith("'")) ||
                (valueStr.startsWith("\"") && valueStr.endsWith("\""))) {
            return valueStr.substring(1, valueStr.length() - 1);
        }

        // 处理数字
        try {
            if (valueStr.contains(".")) {
                return Double.parseDouble(valueStr);
            } else {
                return Long.parseLong(valueStr);
            }
        } catch (NumberFormatException e) {
            // 不是数字，返回原字符串
            return valueStr;
        }
    }

    /**
     * 提取WHERE子句
     */
    public static Map<String, Object> extractWhereClause(String sql, Map<String, Object> paramMap) {
        Map<String, Object> whereConditions = new LinkedHashMap<>();

        String upperSql = sql.toUpperCase();
        int whereIndex = upperSql.indexOf("WHERE");

        if (whereIndex == -1) {
            return whereConditions; // 没有WHERE子句
        }

        String whereClause = sql.substring(whereIndex + 5).trim();

        // 简单的WHERE条件解析，支持AND连接
        // 注意：这里只处理简单情况，复杂WHERE条件需要更完善的解析器
        String[] conditions = whereClause.split("(?i)\\s+AND\\s+");

        for (String condition : conditions) {
            condition = condition.trim();
            if (condition.isEmpty()) continue;

            // 处理括号
            condition = condition.replaceAll("^\\(|\\)$", "");

            // 按等号分割
            String[] parts = condition.split("=", 2);
            if (parts.length != 2) {
                continue; // 跳过不支持的格式
            }

            String fieldName = parts[0].trim();
            String valueStr = parts[1].trim();

            // 处理值
            Object value = null;

            if (valueStr.equals("?")) {
                // 预处理参数
                value = paramMap.get(fieldName.toLowerCase());
                if (value == null) {
                    // 尝试从Map中查找
                    for (Map.Entry<String, Object> entry : paramMap.entrySet()) {
                        if (entry.getKey().equalsIgnoreCase(fieldName) ||
                                entry.getKey().toLowerCase().contains(fieldName.toLowerCase())) {
                            value = entry.getValue();
                            break;
                        }
                    }
                }
            } else {
                // 字面值
                value = parseValue(valueStr);
            }

            whereConditions.put(fieldName, value);
        }

        return whereConditions;
    }

    /**
     * 生成查询语句
     */
    public static String generateSelectSql(String tableName, Map<String, Object> whereConditions) {
        StringBuilder selectSql = new StringBuilder("SELECT ");
        selectSql.append("*");

        selectSql.append(" FROM ").append(tableName);

        // 添加WHERE条件
        if (!whereConditions.isEmpty()) {
            selectSql.append(" WHERE ");

            List<String> conditions = new ArrayList<>();
            for (Map.Entry<String, Object> entry : whereConditions.entrySet()) {
                String field = entry.getKey();
                Object value = entry.getValue();

                if (value == null) {
                    conditions.add(field + " IS NULL");
                } else {
                    conditions.add(field + " = " + formatValueForSql(value));
                }
            }

            selectSql.append(String.join(" AND ", conditions));
        }

        return selectSql.toString();
    }

    /**
     * 格式化值为SQL字符串
     */
    private static String formatValueForSql(Object value) {
        if (value == null) {
            return "NULL";
        }

        if (value instanceof String) {
            return "'" + value.toString().replace("'", "''") + "'";
        }

        if (value instanceof Number) {
            return value.toString();
        }

        if (value instanceof Boolean) {
            return ((Boolean) value) ? "1" : "0";
        }

        // 其他类型转为字符串
        return "'" + value.toString().replace("'", "''") + "'";
    }


    public static void main(String[] args) {
        // 测试包含特殊情况的SQL
//        String sql1 = "UPDATE system_users SET email = ? WHERE ID = ?";
//        String sql2 = "UPDATE users SET name = 'John?' WHERE id = ?"; // 字符串中有问号
//        String sql3 = "SELECT * FROM users -- 这是一个注释\nWHERE name = ? AND age > ?";
//        String sql4 = "/* 多行注释 */ INSERT INTO users(name) VALUES(?) /* 另一个注释 */";
//        String sql5 = "INSERT INTO test(col1, col2) VALUES(?, 'test?') WHERE id = ?";
//
//        System.out.println("增强版统计方法:");
//        System.out.println("SQL1: " + sql1 + " -> 占位符数量: " + countPlaceholdersEnhanced(sql1));
//        System.out.println("SQL2: " + sql2 + " -> 占位符数量: " + countPlaceholdersEnhanced(sql2));
//        System.out.println("SQL3: " + sql3 + " -> 占位符数量: " + countPlaceholdersEnhanced(sql3));
//        System.out.println("SQL4: " + sql4 + " -> 占位符数量: " + countPlaceholdersEnhanced(sql4));
//        System.out.println("SQL5: " + sql5 + " -> 占位符数量: " + countPlaceholdersEnhanced(sql5));

        // 示例1: 预处理语句
        System.out.println("=== 示例1: 预处理语句 ===");
        String sql1 = "UPDATE system_users SET email = ? WHERE ID = ?";
        HashMap<String, Object> paramMap1 = new HashMap<>();
        paramMap1.put("email", "test@example.com");
        paramMap1.put("ID", 123);
        paramMap1.put("param1", "test@example.com");
        paramMap1.put("param2", 123);

//        printResult(sql1, paramMap1);


        // 示例2: 带实际值的SQL
        System.out.println("\n=== 示例2: 带实际值的SQL ===");
        String sql2 = "UPDATE employees SET name = 'John Doe', age = 30, salary = 5000.00 WHERE department = 'IT' AND status = 1";
        HashMap<String, Object> paramMap2 = new HashMap<>(); // 可以为空

//        printResult(sql2, paramMap2);

        // 示例3: 多个SET字段
        System.out.println("\n=== 示例3: 多个SET字段 ===");
        String sql3 = "UPDATE products SET price = ?, quantity = ?, updated_by = 'admin' WHERE id = ? AND category = 'electronics'";
        HashMap<String, Object> paramMap3 = new HashMap<>();
        paramMap3.put("price", 99.99);
        paramMap3.put("quantity", 50);
        paramMap3.put("id", 1001);
        paramMap3.put("param1", 99.99);
        paramMap3.put("param2", 50);
        paramMap3.put("param3", 1001);

//        printResult(sql3, paramMap3);

    }


    private static void printResult(String sql, HashMap<String, Object> parameterMap, List<ParameterMapping> parameterMappingList) {
        // 1. 提取表名
        String tableName = DataSecurityUtils.extractTableName(sql);
        log.info("解析到 SQL 中的表名: {}", tableName);


        // 2. 提取SET子句中的字段和值
        Map<String, Object> map = DataSecurityUtils.extractSetClause(sql, parameterMap, parameterMappingList);
        System.out.println("更新字段及值: " + JSON.toJSONString(map));

        // 3. 提取WHERE条件
        Map<String, Object> whereConditions = DataSecurityUtils.extractWhereClause(sql, parameterMap);
        log.info("解析到 SQL 中的whereConditions: {}", whereConditions);

        // 4. 生成查询语句
        String selectSql = DataSecurityUtils.generateSelectSql(tableName, whereConditions);
        log.info("解析到 SQL 中的selectSql: {}", selectSql);
    }


    /**
     * 获取实体的主键字段
     */
    public static String getPrimaryKeyField(Class<?> entityClass) {
        // 查找@TableId注解
        for (Field field : entityClass.getDeclaredFields()) {
            TableId tableIdAnnotation = field.getAnnotation(TableId.class);
            if (tableIdAnnotation != null) {
                return field.getName();
            }
        }

        // 查找@Id注解（JPA）
//        for (Field field : entityClass.getDeclaredFields()) {
//            jakarta.persistence.Id idAnnotation = field.getAnnotation(jakarta.persistence.Id.class);
//            if (idAnnotation != null) {
//                return field.getName();
//            }
//        }

        // 默认使用"id"
        return "id";
    }

    public static Object getFieldValue(Object obj, String fieldName) {
        try {
            // 1. 获取对象的 Class 对象
            Class<?> clazz = obj.getClass();

            // 2. 获取指定名称的 Field 对象
            Field field = clazz.getDeclaredField(fieldName);

            // 3. 设置可访问性（重要！对于私有属性必须调用）
            field.setAccessible(true);

            // 4. 获取属性值
            return field.get(obj);

        } catch (NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
            return null;
        }
    }
}
