package cn.org.cherry.data.security.info;

import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import lombok.Getter;
import lombok.Setter;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.scripting.defaults.RawSqlSource;
import org.apache.ibatis.scripting.xmltags.DynamicSqlSource;

import java.lang.reflect.Field;
import java.util.Map;

/**
 * MyBatis-Plus 更新操作类型枚举
 * 用于在SQL拦截器中准确识别不同的更新方法调用
 */
@Getter
public enum UpdateType {

    INSERT("根据实体插入"),

    /**
     * 根据主键更新单个实体
     * 对应: userMapper.updateById(entity)
     */
    UPDATE_BY_ID("根据主键更新"),

    /**
     * 仅通过Wrapper更新（SET和WHERE都在Wrapper中）
     * 对应: userMapper.update(wrapper) 或 userMapper.update(null, wrapper)
     */
    UPDATE_WITH_WRAPPER_ONLY("仅通过Wrapper更新"),

    /**
     * 实体+QueryWrapper更新
     * 对应: userMapper.update(entity, queryWrapper)
     */
    UPDATE_ENTITY_WITH_QUERY_WRAPPER("实体+QueryWrapper更新"),

    /**
     * 实体+UpdateWrapper更新
     * 对应: userMapper.update(entity, updateWrapper)
     */
    UPDATE_ENTITY_WITH_UPDATE_WRAPPER("实体+UpdateWrapper更新"),

    /**
     * 通过@Update注解执行的自定义SQL更新 目前会走 UPDATE_BY_RAW_SQL
     */
    UPDATE_BY_ANNOTATION("通过@Update注解执行自定义SQL更新"),

    /**
     * 通过XML映射文件执行的原生SQL更新 目前会走 UPDATE_BY_RAW_SQL
     */
    UPDATE_BY_XML_SQL("通过XML执行原生SQL更新"),

    /**
     * 通过@Select注解等非更新操作但执行了更新SQL的情况
     */
    UPDATE_BY_RAW_SQL("原生SQL更新"),

    /**
     * 其他未知更新类型
     */
    UNKNOWN("未知更新类型");

    private final String description;

    UpdateType(String description) {
        this.description = description;
    }

    @Setter
    private Object entity;

    @Setter
    private Object wrapper;


    /**
     * 判断更新类型
     * @param mappedStatement MyBatis的MappedStatement
     * @param parameterObject SQL参数对象
     * @return 更新类型枚举
     */
    public static UpdateType judgeUpdateType(MappedStatement mappedStatement, Object parameterObject) {
        String methodId = mappedStatement.getId();
        String methodName = getShortMethodName(methodId);

        // 1. 检查是否是MyBatis-Plus的内置更新方法
        if (isMyBatisPlusBuiltinMethod(methodName)) {
            return judgeMyBatisPlusUpdateType(methodName, parameterObject);
        }

        // 2. 检查是否是自定义更新（@Update注解或XML）
        return judgeCustomUpdateType(mappedStatement, methodName);
    }

    /**
     * 判断是否是MyBatis-Plus的内置更新方法
     */
    private static boolean isMyBatisPlusBuiltinMethod(String methodName) {
        return "insert".equals(methodName) ||
                "updateById".equals(methodName) ||
                "update".equals(methodName) ||
                "updateBatchById".equals(methodName) ||
                "updateBatch".equals(methodName) ||
                "saveOrUpdate".equals(methodName) ||
                "saveOrUpdateBatch".equals(methodName);
    }

    /**
     * 判断MyBatis-Plus内置方法的更新类型
     */
    private static UpdateType judgeMyBatisPlusUpdateType(String methodName, Object parameterObject) {
        if ("insert".equals(methodName)) {
            return INSERT;
        } else if ("updateById".equals(methodName)) {
            return UPDATE_BY_ID;
        } else if ("update".equals(methodName)) {
            UpdateParamContext paramContext = parseParameters(parameterObject);
            Object entity = paramContext.getEntity();
            Object wrapper = paramContext.getWrapper();
            if (entity != null && wrapper != null) {
                if (wrapper instanceof UpdateWrapper) {
                    UPDATE_ENTITY_WITH_UPDATE_WRAPPER.setEntity(entity);
                    UPDATE_ENTITY_WITH_UPDATE_WRAPPER.setWrapper(wrapper);
                    return UPDATE_ENTITY_WITH_UPDATE_WRAPPER;
                } else if (wrapper instanceof QueryWrapper) {
                    UPDATE_ENTITY_WITH_QUERY_WRAPPER.setEntity(entity);
                    UPDATE_ENTITY_WITH_QUERY_WRAPPER.setWrapper(wrapper);
                    return UPDATE_ENTITY_WITH_QUERY_WRAPPER;
                } else {
                    return UNKNOWN;
                }
            } else if (wrapper != null && (entity == null || isEmptyEntity(entity))) {
                UPDATE_WITH_WRAPPER_ONLY.setEntity(entity);
                UPDATE_WITH_WRAPPER_ONLY.setWrapper(wrapper);
                return UPDATE_WITH_WRAPPER_ONLY;
            } else if (entity != null && wrapper == null) {
                return UNKNOWN;
            }
        }

        return UNKNOWN;
    }

    /**
     * 判断自定义更新的类型
     */
    private static UpdateType judgeCustomUpdateType(MappedStatement mappedStatement, String methodName) {
        // 获取资源文件信息
        String resource = mappedStatement.getResource();

        // 1. 通过资源文件判断是XML还是接口方法
        if (resource != null) {
            if (resource.endsWith(".xml")) {
                return UPDATE_BY_XML_SQL;
            } else if (resource.endsWith(".java")) {
                return UPDATE_BY_ANNOTATION;
            }
        }

        // 2. 通过SqlSource类型判断
        SqlSource sqlSource = mappedStatement.getSqlSource();
        if (sqlSource != null) {
            String sqlSourceClassName = sqlSource.getClass().getSimpleName();

            // 原生SQL类型
            if (sqlSource instanceof RawSqlSource ||
                    sqlSourceClassName.contains("RawSqlSource") ||
                    sqlSourceClassName.contains("StaticSqlSource")) {
                return UPDATE_BY_RAW_SQL;
            }

            // 动态SQL类型（可能来自XML或注解中的动态SQL）
            if (sqlSource instanceof DynamicSqlSource ||
                    sqlSourceClassName.contains("DynamicSqlSource")) {
                // 进一步判断是否是@Select注解等
                SqlCommandType sqlCommandType = mappedStatement.getSqlCommandType();
                if (sqlCommandType == SqlCommandType.SELECT) {
                    // 如果是SELECT命令但执行了更新，可能是@Select注解中包含更新操作
                    return UPDATE_BY_RAW_SQL;
                }
                return UPDATE_BY_XML_SQL; // 动态SQL通常来自XML
            }
        }

        // 3. 通过SQL语句特征判断
        try {
            BoundSql boundSql = mappedStatement.getBoundSql(null);
            String sql = boundSql.getSql().toLowerCase().trim();

            if (sql.startsWith("update ") ||
                    sql.startsWith("insert ") ||
                    sql.startsWith("delete ")) {
                return UPDATE_BY_RAW_SQL;
            }
        } catch (Exception e) {
            // 忽略异常
        }

        return UNKNOWN;
    }

    /**
     * 获取简短的方法名
     */
    private static String getShortMethodName(String fullMethodId) {
        if (fullMethodId == null) {
            return "";
        }
        int lastDotIndex = fullMethodId.lastIndexOf(".");
        return lastDotIndex >= 0 && lastDotIndex < fullMethodId.length() - 1
                ? fullMethodId.substring(lastDotIndex + 1)
                : fullMethodId;
    }

    /**
     * 解析参数对象
     */
    private static UpdateParamContext parseParameters(Object parameterObject) {
        Object entity = null;
        Object wrapper = null;

        if (parameterObject instanceof Map) {
            Map<?, ?> paramMap = (Map<?, ?>) parameterObject;

            // MyBatis-Plus 参数命名约定
            entity = paramMap.get("et");  // entity参数
            wrapper = paramMap.get("ew"); // wrapper参数

            // 如果没有标准参数名，尝试其他可能的键
            if (entity == null && wrapper == null) {
                for (Object value : paramMap.values()) {
                    if (value != null) {
                        if (isWrapper(value)) {
                            wrapper = value;
                        } else if (isEntity(value)) {
                            entity = value;
                        }
                    }
                }
            }
        } else if (parameterObject != null) {
            // 单个参数，可能是实体或wrapper
            if (isWrapper(parameterObject)) {
                wrapper = parameterObject;
            } else {
                entity = parameterObject;
            }
        }

        return new UpdateParamContext(entity, wrapper);
    }

    /**
     * 判断是否为Wrapper对象
     */
    private static boolean isWrapper(Object obj) {
        return obj instanceof Wrapper;
    }

    /**
     * 判断是否为实体对象
     */
    private static boolean isEntity(Object obj) {
        return !isWrapper(obj) && !(obj instanceof Map);
    }

    /**
     * 判断实体是否为空
     */
    private static boolean isEmptyEntity(Object entity) {
        if (entity == null) {
            return true;
        }

        if (entity instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) entity;
            for (Object value : map.values()) {
                if (value != null) {
                    return false;
                }
            }
            return true;
        }

        // 通过反射检查实体字段是否全部为null
        try {
            Class<?> clazz = entity.getClass();
            for (Field field : clazz.getDeclaredFields()) {
                field.setAccessible(true);
                if (field.get(entity) != null) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 判断是否是XML中定义的SQL
     */
    public static boolean isXmlSql(MappedStatement mappedStatement) {
        String resource = mappedStatement.getResource();
        return resource != null && resource.endsWith(".xml");
    }

    /**
     * 获取SQL语句
     */
    public static String getSql(MappedStatement mappedStatement) {
        try {
            BoundSql boundSql = mappedStatement.getBoundSql(null);
            return boundSql.getSql();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 参数上下文类，封装解析结果
     */
    @Getter
    private static class UpdateParamContext {
        private final Object entity;
        private final Object wrapper;

        public UpdateParamContext(Object entity, Object wrapper) {
            this.entity = entity;
            this.wrapper = wrapper;
        }

    }
}
