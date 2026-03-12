package cn.org.cherry.data.security.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.core.type.ClassMetadata;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.core.type.classreading.MetadataReaderFactory;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.core.type.filter.TypeFilter;
import org.springframework.util.ClassUtils;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.net.URL;
import java.util.*;
import java.util.function.Predicate;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.stream.Collectors;

/**
 * 实体类扫描器
 * 用于扫描指定包下带有特定注解的类
 */
public class EntityScanner {

    private static final String CLASS_SUFFIX = ".class";
    private static final String PACKAGE_SEPARATOR = ".";
    private static final String PATH_SEPARATOR = "/";
    private static final String CLASS_FILE_SUFFIX = ".class";
    private static final String JAR_FILE_SUFFIX = ".jar";
    private static final Logger log = LoggerFactory.getLogger(EntityScanner.class);

    // 缓存Spring Boot启动类
    private static Class<?> springBootApplicationClass = null;

    /**
     * 获取Spring Boot启动类
     */
    public static Class<?> findSpringBootApplicationClass() {
        if (springBootApplicationClass != null) {
            return springBootApplicationClass;
        }

        // 方法1：从线程栈中查找
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stackTrace) {
            try {
                Class<?> clazz = Class.forName(element.getClassName());
                if (clazz.isAnnotationPresent(org.springframework.boot.autoconfigure.SpringBootApplication.class)) {
                    springBootApplicationClass = clazz;
                    return clazz;
                }
            } catch (ClassNotFoundException | NoClassDefFoundError e) {
                // 忽略无法加载的类
            }
        }

        // 方法2：查找包含main方法的类
        for (StackTraceElement element : stackTrace) {
            try {
                Class<?> clazz = Class.forName(element.getClassName());
                clazz.getMethod("main", String[].class);
                // 检查是否有SpringBootApplication注解
                if (clazz.isAnnotationPresent(org.springframework.boot.autoconfigure.SpringBootApplication.class)) {
                    springBootApplicationClass = clazz;
                    return clazz;
                }
            } catch (ClassNotFoundException | NoClassDefFoundError | NoSuchMethodException e) {
                // 继续查找
            }
        }

        // 方法3：如果找不到，返回调用者类
        try {
            Class<?> clazz = Class.forName(stackTrace[stackTrace.length - 1].getClassName());
            springBootApplicationClass = clazz;
            return clazz;
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("无法找到Spring Boot启动类", e);
        }
    }

    public static List<Class<?>> scanEntitiesWithAnnotation(Class<? extends Annotation> annotationClass,Class<?> applicationClass) {
        return scanEntitiesWithAnnotation(annotationClass,applicationClass, (String) null);
    }

    /**
     * 扫描指定包下带有指定注解的实体类
     *
     * @param annotationClass 注解类
     * @param packages 要扫描的包路径数组
     * @return 找到的实体类列表
     */
    public static List<Class<?>> scanEntitiesWithAnnotation(Class<? extends Annotation> annotationClass,Class<?> applicationClass,
                                                            String... packages) {
        if (packages == null || packages.length == 0 || packages[0] == null || packages[0].isEmpty()) {
            // 如果包名为空，则获取默认包（启动类所在的包的前两个包）
            packages = getDefaultPackages(applicationClass);
        }

        Set<Class<?>> result = new LinkedHashSet<>();
        MetadataReaderFactory metadataReaderFactory = new SimpleMetadataReaderFactory();

        for (String basePackage : packages) {
            if (basePackage == null || basePackage.trim().isEmpty()) {
                continue;
            }
            try {
                // 转换为资源路径模式
                String packageSearchPath = ResourcePatternResolver.CLASSPATH_ALL_URL_PREFIX + resolveBasePackage(basePackage) + "/" + "**/*" + CLASS_SUFFIX;

                ResourcePatternResolver resourcePatternResolver = new PathMatchingResourcePatternResolver();
                Resource[] resources = resourcePatternResolver.getResources(packageSearchPath);

                // 创建注解过滤器
                TypeFilter annotationFilter = new AnnotationTypeFilter(annotationClass, false);

                for (Resource resource : resources) {
                    if (resource.isReadable()) {
                        try {
                            MetadataReader metadataReader = metadataReaderFactory.getMetadataReader(resource);
                            ClassMetadata classMetadata = metadataReader.getClassMetadata();

                            // 检查是否是注解类
                            if (classMetadata.isAnnotation() ||
                                    classMetadata.isInterface() ||
                                    classMetadata.isAbstract()) {
                                continue;
                            }

                            // 检查是否带有指定注解
                            if (annotationFilter.match(metadataReader, metadataReaderFactory)) {
                                String className = classMetadata.getClassName();
                                Class<?> clazz = Class.forName(className);
                                result.add(clazz);
                            }
                        } catch (ClassNotFoundException | NoClassDefFoundError e) {
                            // 忽略无法加载的类
                            System.err.println("无法加载类: " + resource.getFilename() + ", 错误: " + e.getMessage());
                        } catch (IOException e) {
                            System.err.println("读取资源时出错: " + resource.getFilename() + ", 错误: " + e.getMessage());
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println("扫描包路径时出错: " + basePackage + ", 错误: " + e.getMessage());
            }
        }

        return new ArrayList<>(result);
    }

    /**
     * 获取默认包路径（启动类所在的包的前两个包）
     */
    private static String[] getDefaultPackages(Class<?> mainClass) {
        try {
            // 2. 获取包名
            Package pkg = mainClass.getPackage();
            if (pkg == null) {
                throw new RuntimeException("无法获取启动类的包信息");
            }

            String packageName = pkg.getName();

            // 3. 分割包名，获取前两个包
            String[] packageParts = packageName.split("\\.");

            if (packageParts.length >= 2) {
                // 前两个包
                String firstTwoPackages = packageParts[0] + "." + packageParts[1];

                // 返回两种模式：
                // 1. 精确的前两个包
                // 2. 前两个包下的所有子包
                return new String[]{
                        firstTwoPackages,  // 例如: com.example
                        firstTwoPackages + ".**"  // 例如: com.example.**
                };
            } else if (packageParts.length == 1) {
                // 只有一个包
                return new String[]{packageName, packageName + ".**"};
            } else {
                // 没有包（默认包）
                throw new RuntimeException("启动类在默认包中，无法获取前两个包");
            }

        } catch (Exception e) {
            System.err.println("获取默认包失败: " + e.getMessage());
            log.error(e.getMessage(), e);
            // 返回空数组，让调用者处理
            return new String[0];
        }
    }

    /**
     * 解析基础包路径
     */
    private static String resolveBasePackage(String basePackage) {
        return ClassUtils.convertClassNameToResourcePath(basePackage);
    }

    /**
     * 扩展方法：扫描指定包下所有实体类（不限于特定注解）
     *
     * @param packages 要扫描的包路径数组
     * @return 找到的实体类列表
     */
    public static List<Class<?>> scanAllEntities(Class<?> applicationClass,String... packages) {
        return scanEntitiesWithPredicate(null,applicationClass, packages);
    }

    /**
     * 使用条件谓词扫描实体类
     *
     * @param predicate 过滤条件
     * @param packages 要扫描的包路径数组
     * @return 找到的实体类列表
     */
    public static List<Class<?>> scanEntitiesWithPredicate(Predicate<Class<?>> predicate,Class<?> applicationClass,
                                                           String... packages) {
        if (packages == null || packages.length == 0) {
            packages = getDefaultPackages(applicationClass);
        }

        List<Class<?>> result = new ArrayList<>();
        MetadataReaderFactory metadataReaderFactory = new SimpleMetadataReaderFactory();

        for (String basePackage : packages) {
            if (basePackage == null || basePackage.trim().isEmpty()) {
                continue;
            }

            try {
                String packageSearchPath = ResourcePatternResolver.CLASSPATH_ALL_URL_PREFIX +
                        resolveBasePackage(basePackage) + "/" + "**/*" + CLASS_SUFFIX;

                ResourcePatternResolver resourcePatternResolver = new PathMatchingResourcePatternResolver();
                Resource[] resources = resourcePatternResolver.getResources(packageSearchPath);

                for (Resource resource : resources) {
                    if (resource.isReadable()) {
                        try {
                            MetadataReader metadataReader = metadataReaderFactory.getMetadataReader(resource);
                            ClassMetadata classMetadata = metadataReader.getClassMetadata();

                            // 跳过接口、注解、抽象类
                            if (classMetadata.isInterface() ||
                                    classMetadata.isAnnotation() ||
                                    classMetadata.isAbstract()) {
                                continue;
                            }

                            String className = classMetadata.getClassName();
                            Class<?> clazz = Class.forName(className);

                            // 如果提供了谓词，则使用谓词过滤
                            if (predicate == null || predicate.test(clazz)) {
                                result.add(clazz);
                            }
                        } catch (ClassNotFoundException | NoClassDefFoundError e) {
                            // 忽略无法加载的类
                        } catch (IOException e) {
                            System.err.println("读取资源时出错: " + resource.getFilename());
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println("扫描包路径时出错: " + basePackage);
            }
        }

        return result;
    }

    /**
     * 扫描实现特定接口的类
     *
     * @param interfaceClass 接口类
     * @param packages 要扫描的包路径数组
     * @return 找到的实现类列表
     */
    public static List<Class<?>> scanEntitiesImplementingInterface(Class<?> interfaceClass,
                                                                   Class<?> applicationClass,
                                                                   String... packages) {
        return scanEntitiesWithPredicate(clazz -> {
            if (!interfaceClass.isInterface()) {
                return false;
            }
            return interfaceClass.isAssignableFrom(clazz) && !interfaceClass.equals(clazz);
        },applicationClass, packages);
    }

    /**
     * 扩展方法：扫描指定包下带有多个注解的实体类
     *
     * @param annotationClasses 注解类数组
     * @param packages 要扫描的包路径数组
     * @return 找到的实体类列表
     */
    public static List<Class<?>> scanEntitiesWithAnnotations(Class<? extends Annotation>[] annotationClasses,
                                                             Class<?> applicationClass,
                                                             String... packages) {
        return scanEntitiesWithPredicate(clazz -> {
            for (Class<? extends Annotation> annotationClass : annotationClasses) {
                if (!clazz.isAnnotationPresent(annotationClass)) {
                    return false;
                }
            }
            return true;
        },applicationClass, packages);
    }

    /**
     * 获取指定包下的所有类名（不加载类）
     *
     * @param packages 要扫描的包路径数组
     * @return 类名列表
     */
    public static List<String> scanClassNames(String... packages) {
        List<String> classNames = new ArrayList<>();

        for (String basePackage : packages) {
            if (basePackage == null || basePackage.trim().isEmpty()) {
                continue;
            }

            try {
                String packageSearchPath = ResourcePatternResolver.CLASSPATH_ALL_URL_PREFIX +
                        resolveBasePackage(basePackage) + "/" + "**/*" + CLASS_SUFFIX;

                ResourcePatternResolver resourcePatternResolver = new PathMatchingResourcePatternResolver();
                Resource[] resources = resourcePatternResolver.getResources(packageSearchPath);

                for (Resource resource : resources) {
                    if (resource.isReadable()) {
                        try {
                            String resourceUri = resource.getURI().toString();
                            String className = convertResourceToClassName(resourceUri, basePackage);
                            if (className != null) {
                                classNames.add(className);
                            }
                        } catch (IOException e) {
                            // 忽略无法读取的资源
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println("扫描包路径时出错: " + basePackage);
            }
        }

        return classNames;
    }

    /**
     * 将资源路径转换为类名
     */
    private static String convertResourceToClassName(String resourceUri, String basePackage) {
        String basePath = resolveBasePackage(basePackage);

        if (resourceUri.contains(basePath)) {
            int startIndex = resourceUri.indexOf(basePath);
            String relativePath = resourceUri.substring(startIndex);

            // 移除 .class 后缀
            if (relativePath.endsWith(CLASS_FILE_SUFFIX)) {
                relativePath = relativePath.substring(0, relativePath.length() - CLASS_FILE_SUFFIX.length());
            }

            // 将路径分隔符替换为包分隔符
            relativePath = relativePath.replace(PATH_SEPARATOR, PACKAGE_SEPARATOR);

            return relativePath;
        }

        return null;
    }

    /**
     * 缓存已扫描的实体类
     */
    private static final Map<String, List<Class<?>>> entityCache = new HashMap<>();

    /**
     * 带缓存的实体类扫描
     *
     * @param annotationClass 注解类
     * @param packages 要扫描的包路径数组
     * @param useCache 是否使用缓存
     * @return 找到的实体类列表
     */
    public static List<Class<?>> scanEntitiesWithAnnotationCached(Class<? extends Annotation> annotationClass,
                                                                  Class<?> applicationClass,
                                                                  String[] packages,
                                                                  boolean useCache) {
        String cacheKey = generateCacheKey(annotationClass, packages);

        if (useCache && entityCache.containsKey(cacheKey)) {
            return entityCache.get(cacheKey);
        }

        List<Class<?>> entities = scanEntitiesWithAnnotation(annotationClass,applicationClass, packages);

        if (useCache) {
            entityCache.put(cacheKey, entities);
        }

        return entities;
    }

    /**
     * 生成缓存键
     */
    private static String generateCacheKey(Class<? extends Annotation> annotationClass, String[] packages) {
        StringBuilder keyBuilder = new StringBuilder();
        keyBuilder.append(annotationClass.getName()).append(":");

        if (packages != null) {
            Arrays.sort(packages);
            for (String pkg : packages) {
                if (pkg != null) {
                    keyBuilder.append(pkg).append(",");
                }
            }
        }

        return keyBuilder.toString();
    }

    /**
     * 清空缓存
     */
    public static void clearCache() {
        entityCache.clear();
    }
}
