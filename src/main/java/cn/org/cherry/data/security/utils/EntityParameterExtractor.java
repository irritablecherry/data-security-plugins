package cn.org.cherry.data.security.utils;

import cn.org.cherry.data.security.annotation.IdentificationCode;
import cn.org.cherry.data.security.exception.DataSecurityException;
import com.baomidou.mybatisplus.core.conditions.AbstractWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.toolkit.Constants;
import com.baomidou.mybatisplus.core.toolkit.ReflectionKit;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import com.baomidou.mybatisplus.extension.toolkit.SqlHelper;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.SystemMetaObject;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 实体对象提取器
 * 从 MyBatis/MyBatis-Plus 的各种参数中提取实体对象
 */
@Slf4j
public class EntityParameterExtractor {

    // 缓存映射语句的实体类信息
    private static final Map<String, Class<?>> ENTITY_CLASS_CACHE = new ConcurrentHashMap<>();

    // 缓存 Mapper 接口的泛型信息
    private static final Map<Class<?>, Class<?>> MAPPER_ENTITY_CACHE = new ConcurrentHashMap<>();

    /**
     * 从参数中提取实体对象
     * 支持多种参数类型：
     * 1. 直接传入实体对象
     * 2. Map 参数（包括 @Param 注解的参数）
     * 3. QueryWrapper/UpdateWrapper
     * 4. 多个参数的情况
     * 5. 原生 MyBatis 参数
     */
    public static Object extractEntityFromParameter(Object parameter, MappedStatement mappedStatement, Class<?> tableMapClazz) {
        if (parameter == null) {
            return null;
        }

        // 1. 如果是实体对象，直接返回
        if (isEntityObject(parameter)) {
            return parameter;
        }

        // 2. 如果是 Map 参数
        if (parameter instanceof Map) {
            return extractEntityFromMap((Map<?, ?>) parameter, mappedStatement, tableMapClazz);
        }

        // 3. 如果是 Wrapper
        if (parameter instanceof AbstractWrapper) {
            return extractEntityFromWrapper((AbstractWrapper<?, ?, ?>) parameter, mappedStatement);
        }

        // 4. 如果是数组（多个参数）
        if (parameter.getClass().isArray()) {
            return extractEntityFromArray((Object[]) parameter, mappedStatement, tableMapClazz);
        }

        // 5. 如果是集合
        if (parameter instanceof Collection) {
            return extractEntityFromCollection((Collection<?>) parameter, mappedStatement, tableMapClazz);
        }

        // 6. 尝试从 MetaObject 中提取
        try {
            MetaObject metaObject = SystemMetaObject.forObject(parameter);
            return extractEntityFromMetaObject(metaObject, mappedStatement);
        } catch (Exception e) {
            log.debug("从 MetaObject 提取实体失败：parameterType={}, error={}", 
                     parameter.getClass().getName(), e.getMessage());
        }

        return null;
    }

    /**
     * 判断是否是实体对象
     */
    private static boolean isEntityObject(Object obj) {
        if (obj == null) {
            return false;
        }

        Class<?> clazz = obj.getClass();

        // 排除常见的基本类型和包装类
        if (clazz.isPrimitive() ||
                Number.class.isAssignableFrom(clazz) ||
                CharSequence.class.isAssignableFrom(clazz) ||
                Boolean.class.isAssignableFrom(clazz) ||
                Date.class.isAssignableFrom(clazz) ||
                clazz.isEnum() ||
                clazz.isArray() ||
                Collection.class.isAssignableFrom(clazz) ||
                Map.class.isAssignableFrom(clazz) ||
                clazz.getName().startsWith("java.") ||
                clazz.getName().startsWith("javax.")) {
            return false;
        }

        // 检查是否有 @TableName 注解（MyBatis-Plus）
        if (clazz.isAnnotationPresent(com.baomidou.mybatisplus.annotation.TableName.class)) {
            return true;
        }

//        // 检查是否有 @Table 注解（JPA）
//        if (clazz.isAnnotationPresent(jakarta.persistence.Table.class) ||
//                clazz.isAnnotationPresent(javax.persistence.Table.class)) {
//            return true;
//        }
//
        // 检查是否有 @IdentificationCode 注解
        if (clazz.isAnnotationPresent(IdentificationCode.class)) {
            return true;
        }
//
//        // 检查是否有 @Entity 注解（JPA）
//        if (clazz.isAnnotationPresent(jakarta.persistence.Entity.class) ||
//                clazz.isAnnotationPresent(javax.persistence.Entity.class)) {
//            return true;
//        }

        // 检查是否有 @TableId 或 @Id 注解的字段
        Field[] fields = clazz.getDeclaredFields();
        for (Field field : fields) {
            if (field.isAnnotationPresent(com.baomidou.mybatisplus.annotation.TableId.class)
//                    ||
//                    field.isAnnotationPresent(jakarta.persistence.Id.class) ||
//                    field.isAnnotationPresent(javax.persistence.Id.class)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * 从 Map 参数中提取实体对象
     */
    private static Object extractEntityFromMap(Map<?, ?> paramMap, MappedStatement mappedStatement, Class<?> tableMapClazz) {
        if (paramMap == null || paramMap.isEmpty()) {
            return null;
        }

        // 1. 先尝试从常见的 MyBatis-Plus 键中查找
        Object entity = findEntityByCommonKeys(paramMap);
        if (entity != null) {
            return entity;
        }

        // 2. 遍历 Map 的值，查找实体对象
        for (Object value : paramMap.values()) {
            if (isEntityObject(value)) {
                return value;
            }
        }

        // 3. 尝试从 MappedStatement 获取实体类，然后创建实例并填充
        entity = createEntityFromMap(paramMap, mappedStatement, tableMapClazz);
        if (entity != null) {
            return entity;
        }

        // 4. 检查是否有 entity 参数
        if (paramMap.containsKey("entity")) {
            Object entityParam = paramMap.get("entity");
            if (isEntityObject(entityParam)) {
                return entityParam;
            }
        }

        if (paramMap.containsKey("param1")) {
            // 5. 检查第一个参数（param1）
            Object param1 = paramMap.get("param1");
            if (isEntityObject(param1)) {
                return param1;
            }
        }
        return null;
    }

    /**
     * 从常见的 MyBatis-Plus 键中查找实体
     */
    private static Object findEntityByCommonKeys(Map<?, ?> paramMap) {
        // MyBatis-Plus 常用的键
        String[] commonKeys = {
                Constants.ENTITY,        // "et"
                Constants.WRAPPER,       // "ew"
                Constants.ENTITY_DOT,    // "et."
                "updateParam",           // 更新参数
                "updateWrapper",         // 更新包装器
                "queryWrapper",          // 查询包装器
                "ew.paramNameValuePairs" // Wrapper 中的参数
        };

        for (String key : commonKeys) {
            if (!paramMap.containsKey(key)) {
                continue;
            }
            Object value = paramMap.get(key);
            if (value != null && isEntityObject(value)) {
                return value;
            }

            // 如果是 Wrapper，尝试提取
            if (value instanceof AbstractWrapper) {
                Object entity = extractEntityFromWrapper((AbstractWrapper<?, ?, ?>) value, null);
                if (entity != null) {
                    return entity;
                }
            }
        }

        return null;
    }

    /**
     * 从 Wrapper 中提取实体对象
     */
    private static Object extractEntityFromWrapper(AbstractWrapper<?, ?, ?> wrapper, MappedStatement mappedStatement) {
        if (wrapper == null) {
            return null;
        }

        try {
            // 1. 尝试调用 getEntity 方法（如果有）
            Method getEntityMethod = wrapper.getClass().getMethod("getEntity");
            if (getEntityMethod != null) {
                Object entity = getEntityMethod.invoke(wrapper);
                if (entity != null && isEntityObject(entity)) {
                    return entity;
                }
            }
        } catch (Exception e) {
            // 方法不存在或无权限，忽略
        }

        // 2. 尝试从 Wrapper 的 paramNameValuePairs 中提取
        try {
            Field paramNameValuePairsField = ReflectionUtils.findField(
                    wrapper.getClass(), "paramNameValuePairs");

            if (paramNameValuePairsField != null) {
                paramNameValuePairsField.setAccessible(true);
                Object paramNameValuePairs = paramNameValuePairsField.get(wrapper);

                if (paramNameValuePairs instanceof Map) {
                    Map<?, ?> paramMap = (Map<?, ?>) paramNameValuePairs;
                    for (Object value : paramMap.values()) {
                        if (isEntityObject(value)) {
                            return value;
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("从 Wrapper 参数名值对提取实体失败：wrapperType={}, error={}", 
                     wrapper != null ? wrapper.getClass().getName() : "null", e.getMessage());
        }

        // 3. 尝试获取 UpdateWrapper 的实体
        if (wrapper instanceof UpdateWrapper) {
            UpdateWrapper<?> updateWrapper = (UpdateWrapper<?>) wrapper;
            try {
                Field entityField = ReflectionUtils.findField(updateWrapper.getClass(), "entity");
                if (entityField != null) {
                    entityField.setAccessible(true);
                    Object entity = entityField.get(updateWrapper);
                    if (entity != null && isEntityObject(entity)) {
                        return entity;
                    }
                }
            } catch (Exception e) {
                log.debug("从 UpdateWrapper 提取实体失败：error={}", e.getMessage());
            }
        }

        // 4. 从 SQL 中解析实体类并创建实例
        return createEntityFromWrapper(wrapper, mappedStatement);
    }

    /**
     * 从数组中提取实体对象
     */
    private static Object extractEntityFromArray(Object[] array, MappedStatement mappedStatement, Class<?> tableMapClazz) {
        if (array == null || array.length == 0) {
            return null;
        }

        // 遍历数组，查找实体对象
        for (Object param : array) {
            if (param == null) {
                continue;
            }

            if (isEntityObject(param)) {
                return param;
            }

            // 如果是 Map
            if (param instanceof Map) {
                Object entity = extractEntityFromMap((Map<?, ?>) param, mappedStatement, tableMapClazz);
                if (entity != null) {
                    return entity;
                }
            }

            // 如果是 Wrapper
            if (param instanceof AbstractWrapper) {
                Object entity = extractEntityFromWrapper((AbstractWrapper<?, ?, ?>) param, mappedStatement);
                if (entity != null) {
                    return entity;
                }
            }
        }

        return null;
    }

    /**
     * 从集合中提取实体对象
     */
    private static Object extractEntityFromCollection(Collection<?> collection, MappedStatement mappedStatement, Class<?> tableMapClazz) {
        if (collection == null || collection.isEmpty()) {
            return null;
        }

        // 遍历集合，查找实体对象
        for (Object param : collection) {
            if (param == null) {
                continue;
            }

            if (isEntityObject(param)) {
                return param;
            }

            // 如果是 Map
            if (param instanceof Map) {
                Object entity = extractEntityFromMap((Map<?, ?>) param, mappedStatement, tableMapClazz);
                if (entity != null) {
                    return entity;
                }
            }

            // 如果是 Wrapper
            if (param instanceof AbstractWrapper) {
                Object entity = extractEntityFromWrapper((AbstractWrapper<?, ?, ?>) param, mappedStatement);
                if (entity != null) {
                    return entity;
                }
            }
        }

        return null;
    }

    /**
     * 从 MetaObject 中提取实体对象
     */
    private static Object extractEntityFromMetaObject(MetaObject metaObject, MappedStatement mappedStatement) {
        if (metaObject == null) {
            return null;
        }

        try {
            // 尝试获取原始对象
            Object originalObject = metaObject.getOriginalObject();
            if (originalObject != null && isEntityObject(originalObject)) {
                return originalObject;
            }

            // 尝试遍历属性查找实体
            String[] getterNames = metaObject.getGetterNames();
            for (String getterName : getterNames) {
                try {
                    Object value = metaObject.getValue(getterName);
                    if (value != null && isEntityObject(value)) {
                        return value;
                    }
                } catch (Exception e) {
                    log.debug("从 MetaObject 属性获取值失败：getterName={}, error={}", getterName, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.debug("从 MetaObject 提取实体失败：parameterType={}, error={}", 
                     metaObject != null ? metaObject.getOriginalObject().getClass().getName() : "null", e.getMessage());
        }

        return null;
    }

    /**
     * 从 Map 创建实体对象
     */
    private static Object createEntityFromMap(Map<?, ?> paramMap, MappedStatement mappedStatement, Class<?> tableMapClazz) {
        if (paramMap == null || paramMap.isEmpty()) {
            return null;
        }

        // 获取实体类
        Class<?> entityClass = getEntityClass(mappedStatement);
        if (entityClass == null) {
            return null;
        }

        try {
            // 创建实体实例
            Object entity = entityClass.newInstance();
            MetaObject metaObject = SystemMetaObject.forObject(entity);
            //如果实体和tableMapClazz相同，则从Map中填充实体字段 如果不同则不再给实体赋值
            if ((tableMapClazz != null && tableMapClazz.equals(entityClass))) {
                // 遍历 Map，填充实体字段
                for (Map.Entry<?, ?> entry : paramMap.entrySet()) {
                    String key = entry.getKey().toString();
                    Object value = entry.getValue();
                    // 跳过特殊键
                    if (isSpecialKey(key)) {
                        continue;
                    }
                    // 尝试设置字段值
                    try {
                        if (metaObject.hasSetter(key)) {
                            metaObject.setValue(key, value);
                        }
                    } catch (Exception e) {
                        // 忽略设置失败的字段
                    }
                }
            }
            return entity;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 从 Wrapper 创建实体对象
     */
    private static Object createEntityFromWrapper(AbstractWrapper<?, ?, ?> wrapper, MappedStatement mappedStatement) {
        if (wrapper == null) {
            return null;
        }

        // 获取实体类
        Class<?> entityClass = getEntityClass(mappedStatement);
        if (entityClass == null) {
            return null;
        }

        try {
            // 创建实体实例
            Object entity = entityClass.newInstance();
            MetaObject metaObject = SystemMetaObject.forObject(entity);

            // 尝试从 Wrapper 的 paramNameValuePairs 中获取字段值
            try {
                Field paramNameValuePairsField = ReflectionUtils.findField(
                        wrapper.getClass(), "paramNameValuePairs");

                if (paramNameValuePairsField != null) {
                    paramNameValuePairsField.setAccessible(true);
                    Object paramNameValuePairs = paramNameValuePairsField.get(wrapper);

                    if (paramNameValuePairs instanceof Map) {
                        Map<?, ?> paramMap = (Map<?, ?>) paramNameValuePairs;

                        for (Map.Entry<?, ?> entry : paramMap.entrySet()) {
                            String key = entry.getKey().toString();
                            Object value = entry.getValue();

                            // 跳过特殊键
                            if (isSpecialKey(key)) {
                                continue;
                            }

                            // 尝试设置字段值
                            try {
                                if (metaObject.hasSetter(key)) {
                                    metaObject.setValue(key, value);
                                }
                            } catch (Exception e) {
                                log.debug("设置字段值失败：key={}, error={}", key, e.getMessage());
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.debug("从 Wrapper 参数名值对获取字段失败：wrapperType={}, error={}", 
                         wrapper != null ? wrapper.getClass().getName() : "null", e.getMessage());
            }

            return entity;

        } catch (Exception e) {
            log.debug("从 Wrapper 创建实体失败：wrapperType={}, error={}", 
                     wrapper != null ? wrapper.getClass().getName() : "null", e.getMessage());
            return null;
        }
    }

    /**
     * 获取 MappedStatement 对应的实体类
     */
    private static Class<?> getEntityClass(MappedStatement mappedStatement) {
        if (mappedStatement == null) {
            return null;
        }

        String statementId = mappedStatement.getId();
        if (StringUtils.isBlank(statementId)) {
            return null;
        }

        // 从缓存中获取
        Class<?> cachedEntityClass = ENTITY_CLASS_CACHE.get(statementId);
        if (cachedEntityClass != null) {
            return cachedEntityClass;
        }

        try {
            // 1. 从 Mapper 接口获取实体类
            String mapperClassName = statementId.substring(0, statementId.lastIndexOf('.'));
            Class<?> mapperClass = Class.forName(mapperClassName);

            // 获取实体类（通过泛型）
            Class<?> entityClass = getEntityClassFromMapper(mapperClass);

            if (entityClass != null) {
                ENTITY_CLASS_CACHE.put(statementId, entityClass);
                return entityClass;
            }

            // 2. 尝试从 MyBatis-Plus 的 TableInfoHelper 获取
            try {
                Class<?> tableInfoHelperClass = Class.forName("com.baomidou.mybatisplus.core.metadata.TableInfoHelper");
                Method getTableInfoMethod = tableInfoHelperClass.getMethod("getTableInfo", String.class);
                Object tableInfo = getTableInfoMethod.invoke(null, statementId);

                if (tableInfo != null) {
                    Method getEntityTypeMethod = tableInfo.getClass().getMethod("getEntityType");
                    entityClass = (Class<?>) getEntityTypeMethod.invoke(tableInfo);

                    if (entityClass != null) {
                        ENTITY_CLASS_CACHE.put(statementId, entityClass);
                        return entityClass;
                    }
                }
            } catch (Exception e) {
                log.debug("从 TableInfoHelper 获取实体类失败：statementId={}, error={}", statementId, e.getMessage());
            }

            // 3. 尝试从 SqlHelper 获取
            try {
                Class<?> sqlHelperClass = SqlHelper.class;
                Method getEntityClassMethod = sqlHelperClass.getMethod("entity", Class.class);
                entityClass = (Class<?>) getEntityClassMethod.invoke(null, mapperClass);

                if (entityClass != null) {
                    ENTITY_CLASS_CACHE.put(statementId, entityClass);
                    return entityClass;
                }
            } catch (Exception e) {
                log.debug("从 SqlHelper 获取实体类失败：mapperClass={}, error={}", mapperClass != null ? mapperClass.getName() : "null", e.getMessage());
            }

        } catch (Exception e) {
            log.debug("获取实体类失败：statementId={}, error={}", statementId, e.getMessage());
        }

        return null;
    }

    /**
     * 从 Mapper 接口获取实体类
     */
    private static Class<?> getEntityClassFromMapper(Class<?> mapperClass) {
        if (mapperClass == null) {
            return null;
        }

        // 从缓存中获取
        Class<?> cachedEntityClass = MAPPER_ENTITY_CACHE.get(mapperClass);
        if (cachedEntityClass != null) {
            return cachedEntityClass;
        }

        // 1. 检查是否是 BaseMapper 的子类
        if (BaseMapper.class.isAssignableFrom(mapperClass)) {
            try {
                // 使用 MyBatis-Plus 的工具类获取泛型
                Class<?> entityClass = ReflectionKit.getSuperClassGenericType(mapperClass, BaseMapper.class, 0);
                if (entityClass != null && !Object.class.equals(entityClass)) {
                    MAPPER_ENTITY_CACHE.put(mapperClass, entityClass);
                    return entityClass;
                }
            } catch (Exception e) {
                log.debug("从 BaseMapper 泛型获取实体类失败：mapperClass={}, error={}", mapperClass.getName(), e.getMessage());
            }
        }

        // 2. 遍历泛型接口
        java.lang.reflect.Type[] genericInterfaces = mapperClass.getGenericInterfaces();
        for (java.lang.reflect.Type genericInterface : genericInterfaces) {
            if (genericInterface instanceof java.lang.reflect.ParameterizedType) {
                java.lang.reflect.ParameterizedType parameterizedType = (java.lang.reflect.ParameterizedType) genericInterface;

                // 检查是否是 BaseMapper
                if (parameterizedType.getRawType().equals(BaseMapper.class)) {
                    java.lang.reflect.Type[] typeArguments = parameterizedType.getActualTypeArguments();
                    if (typeArguments.length > 0 && typeArguments[0] instanceof Class) {
                        Class<?> entityClass = (Class<?>) typeArguments[0];
                        MAPPER_ENTITY_CACHE.put(mapperClass, entityClass);
                        return entityClass;
                    }
                }
            }
        }

        // 3. 检查父类
        Class<?> superClass = mapperClass.getSuperclass();
        if (superClass != null && !Object.class.equals(superClass)) {
            Class<?> entityClass = getEntityClassFromMapper(superClass);
            if (entityClass != null) {
                MAPPER_ENTITY_CACHE.put(mapperClass, entityClass);
                return entityClass;
            }
        }

        return null;
    }

    /**
     * 检查是否是特殊键
     */
    private static boolean isSpecialKey(String key) {
        if (StringUtils.isBlank(key)) {
            return true;
        }

        // MyBatis-Plus 的特殊键
        String[] specialKeys = {
                Constants.ENTITY,
                Constants.WRAPPER,
                Constants.ENTITY_DOT,
                "ew",
                "paramNameValuePairs",
                "param1", "param2", "param3", "param4", "param5",
                "param6", "param7", "param8", "param9", "param10"
        };

        for (String specialKey : specialKeys) {
            if (key.equals(specialKey) || key.startsWith(specialKey + ".")) {
                return true;
            }
        }

        return false;
    }

    /**
     * 增强版：从参数中提取实体对象，支持批量操作
     */
    public static List<Object> extractEntitiesFromParameter(Object parameter, MappedStatement mappedStatement, Class<?> tableMapClazz) {
        List<Object> entities = new ArrayList<>();

        if (parameter == null) {
            return entities;
        }

        // 1. 如果是单个实体
        if (isEntityObject(parameter)) {
            entities.add(parameter);
            return entities;
        }

        // 2. 如果是集合（批量操作）
        if (parameter instanceof Collection) {
            for (Object item : (Collection<?>) parameter) {
                if (isEntityObject(item)) {
                    entities.add(item);
                }
            }
            return entities;
        }

        // 3. 如果是数组
        if (parameter.getClass().isArray()) {
            for (Object item : (Object[]) parameter) {
                if (item != null && isEntityObject(item)) {
                    entities.add(item);
                }
            }
            return entities;
        }

        // 4. 尝试提取单个实体
        Object entity = extractEntityFromParameter(parameter, mappedStatement, tableMapClazz);
        if (entity != null) {
            entities.add(entity);
        }

        return entities;
    }

    /**
     * 从参数中提取实体对象列表（支持嵌套结构）
     */
    public static List<Object> extractEntitiesDeeply(Object parameter, MappedStatement mappedStatement) {
        List<Object> entities = new ArrayList<>();

        if (parameter == null) {
            return entities;
        }

        // 递归提取实体
        extractEntitiesRecursive(parameter, mappedStatement, entities, new HashSet<>());

        return entities;
    }

    /**
     * 递归提取实体
     */
    private static void extractEntitiesRecursive(Object param, MappedStatement mappedStatement,
                                                 List<Object> entities, Set<Object> visited) {
        if (param == null || visited.contains(param)) {
            return;
        }

        visited.add(param);

        // 如果是实体对象，添加到列表
        if (isEntityObject(param)) {
            entities.add(param);
            return;
        }

        // 处理集合
        if (param instanceof Collection) {
            for (Object item : (Collection<?>) param) {
                extractEntitiesRecursive(item, mappedStatement, entities, visited);
            }
            return;
        }

        // 处理数组
        if (param.getClass().isArray()) {
            for (Object item : (Object[]) param) {
                extractEntitiesRecursive(item, mappedStatement, entities, visited);
            }
            return;
        }

        // 处理 Map
        if (param instanceof Map) {
            for (Object value : ((Map<?, ?>) param).values()) {
                extractEntitiesRecursive(value, mappedStatement, entities, visited);
            }
            return;
        }

        // 处理 Wrapper
        if (param instanceof AbstractWrapper) {
            try {
                // 尝试获取实体
                Method getEntityMethod = param.getClass().getMethod("getEntity");
                Object entity = getEntityMethod.invoke(param);
                extractEntitiesRecursive(entity, mappedStatement, entities, visited);

                // 尝试获取 paramNameValuePairs
                Field paramNameValuePairsField = ReflectionUtils.findField(
                        param.getClass(), "paramNameValuePairs");

                if (paramNameValuePairsField != null) {
                    paramNameValuePairsField.setAccessible(true);
                    Object pairs = paramNameValuePairsField.get(param);
                    extractEntitiesRecursive(pairs, mappedStatement, entities, visited);
                }
            } catch (Exception e) {
                log.debug("从 Wrapper 提取实体失败：wrapperType={}, error={}", 
                         param.getClass().getName(), e.getMessage());
            }
            return;
        }

        // 如果是其他对象，尝试反射获取字段值
        try {
            Field[] fields = param.getClass().getDeclaredFields();
            for (Field field : fields) {
                field.setAccessible(true);
                Object value = field.get(param);
                extractEntitiesRecursive(value, mappedStatement, entities, visited);
            }
        } catch (Exception e) {
            log.debug("从对象字段提取实体失败：objectType={}, error={}", 
                     param.getClass().getName(), e.getMessage());
        }
    }

    /**
     * 判断是否是插入操作
     */
    public static boolean isInsertOperation(MappedStatement mappedStatement) {
        if (mappedStatement == null) {
            return false;
        }

        String statementId = mappedStatement.getId();
        if (StringUtils.isBlank(statementId)) {
            return false;
        }

        String lowerStatementId = statementId.toLowerCase();

        // 检查是否是插入操作
        return lowerStatementId.contains(".insert") ||
                lowerStatementId.contains(".save") ||
                lowerStatementId.contains("insert") ||
                lowerStatementId.contains("save");
    }

    /**
     * 判断是否是更新操作
     */
    public static boolean isUpdateOperation(MappedStatement mappedStatement) {
        if (mappedStatement == null) {
            return false;
        }

        String statementId = mappedStatement.getId();
        if (StringUtils.isBlank(statementId)) {
            return false;
        }

        String lowerStatementId = statementId.toLowerCase();

        // 检查是否是更新操作
        return lowerStatementId.contains(".update") ||
                lowerStatementId.contains(".modify") ||
                lowerStatementId.contains("update") ||
                lowerStatementId.contains("modify");
    }

    /**
     * 获取操作类型
     */
    public static OperationType getOperationType(MappedStatement mappedStatement) {
        if (mappedStatement == null) {
            return OperationType.UNKNOWN;
        }

        String statementId = mappedStatement.getId();
        if (StringUtils.isBlank(statementId)) {
            return OperationType.UNKNOWN;
        }

        String lowerStatementId = statementId.toLowerCase();

        if (isInsertOperation(mappedStatement)) {
            return OperationType.INSERT;
        }

        if (isUpdateOperation(mappedStatement)) {
            return OperationType.UPDATE;
        }

        if (lowerStatementId.contains(".delete") ||
                lowerStatementId.contains(".remove") ||
                lowerStatementId.contains("delete") ||
                lowerStatementId.contains("remove")) {
            return OperationType.DELETE;
        }

        if (lowerStatementId.contains(".select") ||
                lowerStatementId.contains(".query") ||
                lowerStatementId.contains(".get") ||
                lowerStatementId.contains(".find") ||
                lowerStatementId.contains(".list") ||
                lowerStatementId.contains(".page")) {
            return OperationType.SELECT;
        }

        return OperationType.UNKNOWN;
    }

    /**
     * 操作类型枚举
     */
    public enum OperationType {
        INSERT,
        UPDATE,
        DELETE,
        SELECT,
        UNKNOWN
    }

    /**
     * 获取 Mapper 方法名
     */
    public static String getMapperMethodName(MappedStatement mappedStatement) {
        if (mappedStatement == null) {
            return null;
        }

        String statementId = mappedStatement.getId();
        if (StringUtils.isBlank(statementId)) {
            return null;
        }

        int lastDotIndex = statementId.lastIndexOf('.');
        if (lastDotIndex >= 0 && lastDotIndex < statementId.length() - 1) {
            return statementId.substring(lastDotIndex + 1);
        }

        return statementId;
    }

    /**
     * 获取 Mapper 类名
     */
    public static String getMapperClassName(MappedStatement mappedStatement) {
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
     * 检查参数是否包含实体对象
     */
    public static boolean containsEntity(Object parameter, MappedStatement mappedStatement) {
        if (parameter == null) {
            return false;
        }

        // 快速检查
        if (isEntityObject(parameter)) {
            return true;
        }

        // 深度检查
        List<Object> entities = extractEntitiesDeeply(parameter, mappedStatement);
        return !entities.isEmpty();
    }

    /**
     * 获取实体类的主键值
     */
    public static Object getEntityId(Object entity) {
        if (entity == null) {
            return null;
        }

        try {
            Class<?> entityClass = entity.getClass();
            Field[] fields = entityClass.getDeclaredFields();

            // 查找主键字段
            for (Field field : fields) {
                field.setAccessible(true);

                // 检查 @TableId 注解
                if (field.isAnnotationPresent(com.baomidou.mybatisplus.annotation.TableId.class)) {
                    return field.get(entity);
                }

                // 检查 @Id 注解
//                if (field.isAnnotationPresent(jakarta.persistence.Id.class) ||
//                        field.isAnnotationPresent(javax.persistence.Id.class)) {
//                    return field.get(entity);
//                }

                // 检查字段名是否是 id
                if ("id".equalsIgnoreCase(field.getName())) {
                    return field.get(entity);
                }
            }

            // 检查父类
            Class<?> superClass = entityClass.getSuperclass();
            if (superClass != null && superClass != Object.class) {
                return getEntityIdFromSuperClass(entity, superClass);
            }

        } catch (Exception e) {
            log.debug("获取实体 ID 失败：entityType={}, error={}", 
                     entity != null ? entity.getClass().getName() : "null", e.getMessage());
        }

        return null;
    }

    /**
     * 从父类获取主键
     */
    private static Object getEntityIdFromSuperClass(Object entity, Class<?> superClass) {
        try {
            Field[] fields = superClass.getDeclaredFields();

            for (Field field : fields) {
                field.setAccessible(true);

                // 检查 @TableId 注解
                if (field.isAnnotationPresent(com.baomidou.mybatisplus.annotation.TableId.class)) {
                    return field.get(entity);
                }

                // 检查 @Id 注解
//                if (field.isAnnotationPresent(jakarta.persistence.Id.class) ||
//                        field.isAnnotationPresent(javax.persistence.Id.class)) {
//                    return field.get(entity);
//                }

                // 检查字段名是否是 id
                if ("id".equalsIgnoreCase(field.getName())) {
                    return field.get(entity);
                }
            }

            // 继续向上查找
            Class<?> nextSuperClass = superClass.getSuperclass();
            if (nextSuperClass != null && nextSuperClass != Object.class) {
                return getEntityIdFromSuperClass(entity, nextSuperClass);
            }

        } catch (Exception e) {
            log.debug("从父类获取实体 ID 失败：entityType={}, superClass={}, error={}", 
                     entity != null ? entity.getClass().getName() : "null", 
                     superClass != null ? superClass.getName() : "null", 
                     e.getMessage());
        }

        return null;
    }

    /**
     * 获取实体对象的表名
     */
    public static String getEntityTableName(Object entity) {
        if (entity == null) {
            return null;
        }

        Class<?> entityClass = entity.getClass();

        // 检查 @TableName 注解
        com.baomidou.mybatisplus.annotation.TableName tableNameAnnotation =
                entityClass.getAnnotation(com.baomidou.mybatisplus.annotation.TableName.class);
        if (tableNameAnnotation != null && StringUtils.isNotBlank(tableNameAnnotation.value())) {
            return tableNameAnnotation.value();
        }

//        // 检查 JPA @Table 注解
//        jakarta.persistence.Table jpaTable = entityClass.getAnnotation(jakarta.persistence.Table.class);
//        if (jpaTable != null && StringUtils.isNotBlank(jpaTable.name())) {
//            return jpaTable.name();
//        }
//
//        javax.persistence.Table javaxTable = entityClass.getAnnotation(javax.persistence.Table.class);
//        if (javaxTable != null && StringUtils.isNotBlank(javaxTable.name())) {
//            return javaxTable.name();
//        }

        // 默认：类名转下划线
        return camelToUnderscore(entityClass.getSimpleName());
    }

    /**
     * 驼峰转下划线
     */
    private static String camelToUnderscore(String str) {
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
}
