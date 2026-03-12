package cn.org.cherry.data.security.utils;

import java.lang.reflect.*;
import java.util.*;

/**
 * 从 Mapper 继承链中查找泛型参数
 */
public class MapperGenericFinder {

    /**
     * 获取 Mapper 的实体类（最可靠的方法）
     */
    public static Class<?> findEntityClassFromMapper(Class<?> mapperClass) {
        // 方法1：从泛型接口中查找
        Class<?> entityClass = findFromGenericInterfaces(mapperClass);
        if (entityClass != null) {
            return entityClass;
        }

        // 方法2：从父类中查找
        entityClass = findFromSuperClass(mapperClass);
        if (entityClass != null) {
            return entityClass;
        }

        // 方法3：从实现的接口中递归查找
        entityClass = findFromImplementedInterfaces(mapperClass);
        if (entityClass != null) {
            return entityClass;
        }

        throw new RuntimeException("无法从 Mapper 类中找到实体类: " + mapperClass.getName());
    }

    /**
     * 从泛型接口中查找
     */
    private static Class<?> findFromGenericInterfaces(Class<?> mapperClass) {
        Type[] genericInterfaces = mapperClass.getGenericInterfaces();

        for (Type genericInterface : genericInterfaces) {
            // 先检查是否是 ParameterizedType
            if (genericInterface instanceof ParameterizedType) {
                ParameterizedType paramType = (ParameterizedType) genericInterface;
                Class<?> entityClass = extractEntityClassFromParamType(paramType);
                if (entityClass != null) {
                    return entityClass;
                }
            }
            // 如果是 Class 类型，检查是否是 BaseMapper
            else if (genericInterface instanceof Class) {
                Class<?> ifaceClass = (Class<?>) genericInterface;
                if (isBaseMapper(ifaceClass)) {
                    // 这个接口是 BaseMapper 但没有泛型参数
                    // 需要查找它的父接口
                    Class<?> entityClass = findFromGenericInterfaces(ifaceClass);
                    if (entityClass != null) {
                        return entityClass;
                    }
                }
            }
        }

        return null;
    }

    /**
     * 从父类中查找
     */
    private static Class<?> findFromSuperClass(Class<?> mapperClass) {
        Type genericSuperclass = mapperClass.getGenericSuperclass();

        if (genericSuperclass instanceof ParameterizedType) {
            ParameterizedType paramType = (ParameterizedType) genericSuperclass;
            return extractEntityClassFromParamType(paramType);
        }
        else if (genericSuperclass instanceof Class) {
            Class<?> superClass = (Class<?>) genericSuperclass;
            if (!superClass.equals(Object.class)) {
                return findFromGenericInterfaces(superClass);
            }
        }

        return null;
    }

    /**
     * 从实现的接口中递归查找
     */
    private static Class<?> findFromImplementedInterfaces(Class<?> mapperClass) {
        Class<?>[] interfaces = mapperClass.getInterfaces();

        for (Class<?> iface : interfaces) {
            // 检查是否是 BaseMapper
            if (isBaseMapper(iface)) {
                // 获取这个接口的泛型信息
                Type[] genericInterfaces = iface.getGenericInterfaces();
                for (Type genericInterface : genericInterfaces) {
                    if (genericInterface instanceof ParameterizedType) {
                        ParameterizedType paramType = (ParameterizedType) genericInterface;
                        Class<?> entityClass = extractEntityClassFromParamType(paramType);
                        if (entityClass != null) {
                            return entityClass;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * 从 ParameterizedType 中提取实体类
     */
    private static Class<?> extractEntityClassFromParamType(ParameterizedType paramType) {
        Type rawType = paramType.getRawType();

        // 检查是否是 BaseMapper
        if (rawType instanceof Class && isBaseMapper((Class<?>) rawType)) {
            Type[] typeArgs = paramType.getActualTypeArguments();
            if (typeArgs.length > 0) {
                Type entityType = typeArgs[0];
                return getClassFromType(entityType);
            }
        }

        return null;
    }

    /**
     * 从 Type 获取 Class
     */
    private static Class<?> getClassFromType(Type type) {
        if (type instanceof Class) {
            return (Class<?>) type;
        } else if (type instanceof ParameterizedType) {
            return getClassFromType(((ParameterizedType) type).getRawType());
        } else if (type instanceof GenericArrayType) {
            Type componentType = ((GenericArrayType) type).getGenericComponentType();
            Class<?> componentClass = getClassFromType(componentType);
            if (componentClass != null) {
                return Array.newInstance(componentClass, 0).getClass();
            }
        }
        return null;
    }

    /**
     * 判断是否是 BaseMapper
     */
    private static boolean isBaseMapper(Class<?> clazz) {
        String className = clazz.getName();
        return className.contains("BaseMapper") || className.contains("Mapper");
    }

    /**
     * 通用方法：安全地获取实体类
     */
    public static Class<?> getEntityClassSafely(Class<?> mapperClass) {
        try {
            return findEntityClassFromMapper(mapperClass);
        } catch (Exception e) {
            // 尝试其他方法
            return getEntityClassByReflection(mapperClass);
        }
    }

    /**
     * 通过反射获取实体类
     */
    private static Class<?> getEntityClassByReflection(Class<?> mapperClass) {
        try {
            // 方法1：查找 TYPE 字段
            for (Field field : mapperClass.getDeclaredFields()) {
                if ("TYPE".equals(field.getName()) || "ENTITY_CLASS".equals(field.getName())) {
                    field.setAccessible(true);
                    Object value = field.get(null);
                    if (value instanceof Class) {
                        return (Class<?>) value;
                    }
                }
            }

            // 方法2：查找 getEntityClass 方法
            for (Method method : mapperClass.getDeclaredMethods()) {
                if ("getEntityClass".equals(method.getName()) &&
                        method.getParameterCount() == 0) {
                    method.setAccessible(true);
                    Object result = method.invoke(null);
                    if (result instanceof Class) {
                        return (Class<?>) result;
                    }
                }
            }

        } catch (Exception e) {
            // 忽略异常
        }

        return null;
    }
}
