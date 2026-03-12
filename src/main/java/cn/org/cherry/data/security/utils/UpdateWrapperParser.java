package cn.org.cherry.data.security.utils;

import cn.org.cherry.data.security.annotation.EncryptField;
import cn.org.cherry.data.security.info.SimpleEntity;
import cn.org.cherry.data.security.info.UpdateInfo;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UpdateWrapper解析工具类
 * 用于从UpdateWrapper中提取更新字段、值和SQL片段
 */
public class UpdateWrapperParser {

    private static final Logger logger = LoggerFactory.getLogger(UpdateWrapperParser.class);

    /**
     * 解析UpdateWrapper，获取所有更新信息
     */
    public static UpdateInfo parseUpdateWrapper(UpdateWrapper<?> updateWrapper) {
        UpdateInfo updateInfo = new UpdateInfo();

        if (updateWrapper == null) {
            return updateInfo;
        }

        try {
            // 1. 解析paramNameValuePairs（通过set方法设置的字段值）
            Map<String, Object> fieldValues = parseParamNameValuePairs(updateWrapper);
            updateInfo.setFieldValues(fieldValues);

            // 2. 解析sqlSet（通过setSql方法设置的SQL片段）
            List<String> sqlFragments = parseSqlSet(updateWrapper);
            updateInfo.setSqlFragments(sqlFragments);

            // 3. 解析实体对象（如果通过setEntity设置了实体）
            Object entity = parseEntity(updateWrapper);
            updateInfo.setEntity(entity);

            // 4. 解析条件（WHERE子句）
            Map<String, Object> conditions = parseConditions(updateWrapper);
            updateInfo.setConditions(conditions);

            // 5. 解析SQL字符串
            String sqlSegment = parseSqlSegment(updateWrapper);
            updateInfo.setSqlSegment(sqlSegment);

        } catch (Exception e) {
            logger.error("解析UpdateWrapper失败: {}", e.getMessage(), e);
        }

        return updateInfo;
    }

    /**
     * 解析paramNameValuePairs属性
     * 包含通过set("字段名", 值)方法设置的字段
     */
    public static Map<String, Object> parseParamNameValuePairs(UpdateWrapper<?> updateWrapper) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();

        // 获取AbstractWrapper的paramNameValuePairs属性
        Object paramMap = getFieldValue(updateWrapper, "paramNameValuePairs");

        if (paramMap instanceof Map) {
            Map<?, ?> paramNameValuePairs = (Map<?, ?>) paramMap;

            for (Map.Entry<?, ?> entry : paramNameValuePairs.entrySet()) {
                Object key = entry.getKey();
                Object value = entry.getValue();

                if (key instanceof String) {
                    String fieldName = (String) key;

                    // 解析字段名（去除可能的前缀）
                    String cleanFieldName = cleanFieldName(fieldName);

                    // 解析值
                    Object cleanValue = parseParamValue(value);

                    result.put(cleanFieldName, cleanValue);
                }
            }
        }

        return result;
    }

    /**
     * 解析sqlSet属性
     * 包含通过setSql("字段名 = 表达式")设置的SQL片段
     */
    private static List<String> parseSqlSet(UpdateWrapper<?> updateWrapper) throws Exception {
        List<String> sqlFragments = new ArrayList<>();

        // 获取UpdateWrapper的sqlSet属性
        Object sqlSet = getFieldValue(updateWrapper, "sqlSet");

        if (sqlSet instanceof String) {
            // 如果是字符串，直接添加
            String sql = ((String) sqlSet).trim();
            if (!sql.isEmpty()) {
                sqlFragments.add(sql);
            }
        } else if (sqlSet instanceof List) {
            // 如果是列表，遍历添加
            List<?> sqlList = (List<?>) sqlSet;
            for (Object sqlObj : sqlList) {
                if (sqlObj instanceof String) {
                    String sql = ((String) sqlObj).trim();
                    if (!sql.isEmpty()) {
                        sqlFragments.add(sql);
                    }
                }
            }
        }

        return sqlFragments;
    }

    /**
     * 解析实体对象
     * UpdateWrapper中可能通过setEntity设置了实体
     */
    private static Object parseEntity(UpdateWrapper<?> updateWrapper) throws Exception {
        try {
            // 获取AbstractWrapper的entity属性
            return getFieldValue(updateWrapper, "entity");
        } catch (Exception e) {
            // 实体可能为null
            return null;
        }
    }

    /**
     * 解析WHERE条件
     */
    private static Map<String, Object> parseConditions(UpdateWrapper<?> updateWrapper) throws Exception {
        Map<String, Object> conditions = new LinkedHashMap<>();

        // 尝试获取条件表达式
        try {
            // 获取AbstractWrapper的expression属性
            Object expression = getFieldValue(updateWrapper, "expression");
            if (expression != null) {
                // 如果expression是NormalSegmentList，尝试解析
                String exprStr = expression.toString();
                conditions.put("expression", exprStr);
            }
        } catch (Exception e) {
            // 忽略
        }

        // 尝试获取paramNameValuePairs中的条件参数
        Object paramMap = getFieldValue(updateWrapper, "paramNameValuePairs");
        if (paramMap instanceof Map) {
            Map<?, ?> paramNameValuePairs = (Map<?, ?>) paramMap;

            // 提取条件参数（通常是EW_PARAM开头的）
            for (Map.Entry<?, ?> entry : paramNameValuePairs.entrySet()) {
                Object key = entry.getKey();
                if (key instanceof String && ((String) key).startsWith("ew.paramNameValuePairs")) {
                    Object value = parseParamValue(entry.getValue());
                    conditions.put(key.toString(), value);
                }
            }
        }

        return conditions;
    }

    /**
     * 解析SQL片段
     */
    private static String parseSqlSegment(UpdateWrapper<?> updateWrapper) throws Exception {
        try {
            // 获取AbstractWrapper的sqlSegment属性
            String sqlSegment = (String) getFieldValue(updateWrapper, "sqlSegment");
            return sqlSegment != null ? sqlSegment : "";
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 清理字段名
     * 去除可能的前缀，如paramNameValuePairs.MPGENVAL1.
     */
    private static String cleanFieldName(String fieldName) {
        if (fieldName == null) {
            return "";
        }

        // 去除常见的MyBatis-Plus前缀
        String cleaned = fieldName;

        // 去除paramNameValuePairs.前缀
        if (cleaned.startsWith("paramNameValuePairs.")) {
            cleaned = cleaned.substring("paramNameValuePairs.".length());
        }

        // 去除MPGENVAL前缀
        cleaned = cleaned.replaceAll("MPGENVAL\\d+\\.", "");

        // 去除ew.paramNameValuePairs前缀
        cleaned = cleaned.replaceAll("ew\\.paramNameValuePairs\\d+\\.", "");

        return cleaned;
    }

    /**
     * 解析参数值
     * 处理可能的各种参数类型
     */
    private static Object parseParamValue(Object value) {
        if (value == null) {
            return null;
        }

        // 如果值是ParamNameValue，提取其实际值
        try {
            Class<?> valueClass = value.getClass();

            // 检查是否是ParamNameValue类型
            if (valueClass.getName().contains("ParamNameValue")) {
                // 尝试获取value属性
                Field valueField = valueClass.getDeclaredField("value");
                valueField.setAccessible(true);
                Object actualValue = valueField.get(value);

                // 递归解析
                return parseParamValue(actualValue);
            }

            // 检查是否是ColumnCache对象
            if (valueClass.getName().contains("ColumnCache")) {
                // 尝试获取column属性
                Field columnField = valueClass.getDeclaredField("column");
                columnField.setAccessible(true);
                return columnField.get(value);
            }

        } catch (Exception e) {
            // 如果解析失败，返回原始值
            logger.debug("解析参数值失败: {}, 返回原始值", e.getMessage());
        }

        return value;
    }

    /**
     * 通过反射获取字段值
     */
    private static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Class<?> clazz = obj.getClass();

        // 递归向上查找字段
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException e) {
                // 当前类没有，查找父类
                clazz = clazz.getSuperclass();
            }
        }

        throw new NoSuchFieldException("字段 " + fieldName + " 不存在");
    }

    /**
     * 从SQL片段中提取字段名和表达式
     */
    public static Map<String, String> parseSqlFragments(List<String> sqlFragments) {
        Map<String, String> result = new LinkedHashMap<>();

        if (sqlFragments == null || sqlFragments.isEmpty()) {
            return result;
        }

        for (String fragment : sqlFragments) {
            if (fragment == null || fragment.trim().isEmpty()) {
                continue;
            }

            // 使用正则表达式匹配 字段名 = 表达式
            Pattern pattern = Pattern.compile("([a-zA-Z_][a-zA-Z0-9_]*)\\s*=\\s*(.+)", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(fragment.trim());

            if (matcher.find()) {
                String fieldName = matcher.group(1);
                String expression = matcher.group(2);
                result.put(fieldName, expression);
            } else {
                // 如果不是标准格式，将整个片段作为键，值为空
                result.put(fragment, "");
            }
        }

        return result;
    }

    /**
     * 获取所有更新字段（包括SQL片段中的字段）
     */
    public static Set<String> getAllUpdateFields(UpdateWrapper<?> updateWrapper) {
        Set<String> allFields = new HashSet<>();

        UpdateInfo updateInfo = parseUpdateWrapper(updateWrapper);

        // 添加通过set方法设置的字段
        allFields.addAll(updateInfo.getFieldValues().keySet());

        // 解析SQL片段，提取字段名
        Map<String, String> sqlFragmentFields = parseSqlFragments(updateInfo.getSqlFragments());
        allFields.addAll(sqlFragmentFields.keySet());

        return allFields;
    }

    public static Map<String, Object> getUpdateFieldValues(UpdateWrapper<?> updateWrapper) {
        return getUpdateFieldValues(updateWrapper, null);
    }

    public static Map<String, Object> getUpdateFieldValues(Object entity) {
        return getUpdateFieldValues(null, entity);
    }

    public static Map<String, Object> getEntityFieldValues(Object entity) {
        if (entity == null)
            return Collections.emptyMap();
        try {
            Map<String, Object> result = new LinkedHashMap<>();
            for (Field field : getAllDeclaredFields(entity.getClass())) {
                field.setAccessible(true);
                Object val = field.get(entity);
                if (val != null) {
                    result.put(DataSecurityUtils.camelToUnderscore(field.getName()), val);
                }
            }
            return result;
        } catch (Exception ex) {
            logger.error("解析实体对象字段值失败: {}", ex.getMessage(), ex);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 UpdateWrapper 中要更新的字段名及其对应的值。
     * 合并三类来源：
     *  1) 通过 set("field", value) 设置的 paramNameValuePairs（优先级高）
     *  2) 通过 setEntity(entity) 设置的实体非空字段（作为默认值）
     *  3) 通过 setSql(...) 设置的 SQL 片段，尝试解析其中的参数占位符并解析为实际值，否则返回表达式文本
     * 返回的 Map 保持插入顺序（LinkedHashMap），以便可读性和稳定性 key为数据库字段。
     */
    public static Map<String, Object> getUpdateFieldValues(UpdateWrapper<?> updateWrapper, Object entity) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            // 1. 实体优先加入（作为默认值）
            if (entity != null) {
                for (Field field : getAllDeclaredFields(entity.getClass())) {
                    field.setAccessible(true);
                    Object val = field.get(entity);
                    if (val != null) {
                        result.put(DataSecurityUtils.camelToUnderscore(field.getName()), val);
                    }
                }
            }
            if (updateWrapper == null) {
                return result;
            }
            // 2. 通过 set("field", value) 设置的值（覆盖实体值）
            Map<String, Object> paramValues = parseParamNameValuePairs(updateWrapper);
//            if (paramValues != null && !paramValues.isEmpty()) {
//                result.putAll(paramValues);
//            }

            // 3. 通过 setSql(...) 设置的 SQL 片段，尝试解析参数并放入结果（覆盖前面的）
            List<String> sqlFragments = parseSqlSet(updateWrapper);
            Map<String, String> fragMap = parseSqlFragments(sqlFragments);

            // 获取原始 paramNameValuePairs（未清理的 key），用于解析 SQL 占位符
            Object rawParamObj = null;
            try {
                rawParamObj = getFieldValue(updateWrapper, "paramNameValuePairs");
            } catch (Exception ignored) {
            }
            Map<?, ?> rawParamMap = rawParamObj instanceof Map ? (Map<?, ?>) rawParamObj : Collections.emptyMap();

            for (Map.Entry<String, String> en : fragMap.entrySet()) {
                String fieldName = en.getKey();
                String expr = en.getValue();

                Object resolved = resolveSqlExpressionValue(expr, rawParamMap, paramValues);
                result.put(fieldName, resolved);
            }

        } catch (Exception e) {
            logger.error("解析 UpdateWrapper 更新字段值失败: {}", e.getMessage(), e);
        }

        return result;
    }

    // Helper: 收集类以及父类声明的所有字段
    private static List<Field> getAllDeclaredFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        Class<?> cur = clazz;
        while (cur != null && cur != Object.class) {
            Field[] declared = cur.getDeclaredFields();
            Collections.addAll(fields, declared);
            cur = cur.getSuperclass();
        }
        return fields;
    }

    // Helper: 尝试把 SQL 表达式中的参数占位符解析为实际值
    // 支持形式：#{...}，并会在 rawParamMap 或 cleanedParamMap 中查找对应的参数值
    private static Object resolveSqlExpressionValue(String expr, Map<?, ?> rawParamMap, Map<String, Object> cleanedParamMap) {
        if (expr == null) {
            return null;
        }
        String trimmed = expr.trim();
        try {
            // 查找 MyBatis 占位符 #{...}
            Pattern p = Pattern.compile("#\\{([^}]+)\\}");
            Matcher m = p.matcher(trimmed);
            boolean found = false;
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                found = true;
                String inner = m.group(1); // 可能为 ew.paramNameValuePairs.MPGENVAL1 或 MPGENVAL1 等

                // 1) 直接在 cleanedParamMap 中查找完全匹配的 key
                Object val = null;
                if (cleanedParamMap != null && cleanedParamMap.containsKey(inner)) {
                    val = cleanedParamMap.get(inner);
                }

                // 2) 在 rawParamMap 中查找包含 inner 的 key 或与 inner 相等的 key
                if (val == null && rawParamMap != null) {
                    for (Map.Entry<?, ?> rawEn : rawParamMap.entrySet()) {
                        String rawKey = rawEn.getKey() == null ? "" : rawEn.getKey().toString();
                        if (rawKey.equals(inner) || rawKey.endsWith(inner) || rawKey.contains(inner)) {
                            val = parseParamValue(rawEn.getValue());
                            break;
                        }
                    }
                }

                // 3) 如果仍然没找到，尝试在 cleanedParamMap 中查找 MPGENVAL\d+ 键
                if (val == null && rawParamMap != null) {
                    for (Map.Entry<?, ?> rawEn : rawParamMap.entrySet()) {
                        String rawKey = rawEn.getKey() == null ? "" : rawEn.getKey().toString();
                        if (rawKey.matches(".*MPGENVAL\\\\d+.*")) {
                            // 如果表达式中包含 MPGENVALn，则使用其值
                            if (trimmed.contains(rawKey) || inner.contains("MPGENVAL")) {
                                val = parseParamValue(rawEn.getValue());
                                break;
                            }
                        }
                    }
                }

                String replacement;
                if (val == null) {
                    replacement = m.group(0); // 保持占位符原样
                } else {
                    replacement = val.toString();
                }

                // 转义 $ 等特殊字符
                replacement = Matcher.quoteReplacement(replacement);
                m.appendReplacement(sb, replacement);
            }

            if (found) {
                m.appendTail(sb);
                String replaced = sb.toString();
                // 如果表达式仅仅是一个占位符且被替换为实际值，返回实际值的原始类型
                Pattern onlyPlaceholder = Pattern.compile("^\\s*#\\{([^}]+)\\}\\s*$");
                Matcher onlyM = onlyPlaceholder.matcher(trimmed);
                if (onlyM.find()) {
                    String inner = onlyM.group(1);
                    // 在 cleanedParamMap 或 rawParamMap 中直接返回解析后的真实对象
                    if (inner.contains("ew.paramNameValuePairs.")) {
                        inner = inner.replaceAll("ew.paramNameValuePairs.", "");
                    }
                    if (cleanedParamMap != null && cleanedParamMap.containsKey(inner)) {
                        return cleanedParamMap.get(inner);
                    }
                    if (rawParamMap != null) {
                        for (Map.Entry<?, ?> rawEn : rawParamMap.entrySet()) {
                            String rawKey = rawEn.getKey() == null ? "" : rawEn.getKey().toString();
                            if (rawKey.equals(inner) || rawKey.endsWith(inner) || rawKey.contains(inner)) {
                                return parseParamValue(rawEn.getValue());
                            }
                        }
                    }
                    // 否则返回替换后的文本
                    return replaced;
                }

                return replaced;
            }

            // 如果没有占位符，直接返回表达式文本（例如 NOW()、col + 1 等）
            return trimmed;

        } catch (Exception e) {
            logger.debug("解析 SQL 表达式失败: {}，返回原始表达式", e.getMessage());
            return trimmed;
        }
    }


    public static void main(String[] args) {
//        UpdateWrapper<SimpleEntity> wrapper = new UpdateWrapper<>();
//        wrapper.set("simple_name", "Alice1");
//        wrapper.lambda().set(SimpleEntity::getEmail, "xxx.com");
//        wrapper.set("name", "Alice");
//        wrapper.set("age", 25);
//        wrapper.setSql("updated_at = NOW()");
//        wrapper.eq("id", 123);
//        wrapper.like("name", "Ali");

//        wrapper.getExpression().getNormal().

//        Map<String, Object> map = getUpdateFieldValues(wrapper);
//        System.out.println("更新字段及值: " + JSON.toJSONString(map));

//        QueryWrapper<SimpleEntity> queryWrapper = new QueryWrapper<>();
//        queryWrapper.eq("id", 123);
//        queryWrapper.like("name", "Ali");
//        String whereClause = buildWhereClause(wrapper);
//        System.out.println("WHERE 子句: " + whereClause);
        try {
            SimpleEntity simpleEntity = new SimpleEntity("name", "name", 18, "xxx.com");
            Field field1 = SimpleEntity.class.getDeclaredField("name");
            Field field2 = SimpleEntity.class.getDeclaredField("age");



            EncryptField anno1 = field1.getAnnotation(EncryptField.class);
            EncryptField anno2 = field2.getAnnotation(EncryptField.class);

            System.out.println("注解 " +anno1.hashCode() ); //

            // 1. 比较注解实例本身
            System.out.println("注解实例相同吗？ " + (anno1 == anno2)); // false - 不同的实例

            // 2. 比较annotationType()返回的Class对象
            System.out.println("annotationType相同吗？ " +
                    (anno1.annotationType() == anno2.annotationType())); // true - 同一个Class对象

        } catch (Exception ex) {
            logger.error(ex.getMessage(),ex);
        }

    }
}
