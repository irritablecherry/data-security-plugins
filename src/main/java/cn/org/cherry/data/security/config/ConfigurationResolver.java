package cn.org.cherry.data.security.config;

import cn.org.cherry.data.security.annotation.EncryptField;
import cn.org.cherry.data.security.annotation.IdentificationCode;
import com.baomidou.mybatisplus.annotation.FieldStrategy;
import com.baomidou.mybatisplus.autoconfigure.MybatisPlusProperties;
import com.baomidou.mybatisplus.core.config.GlobalConfig;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 配置优先级解析器
 * <p>
 * 负责解析和合并注解配置与YAML配置文件中的配置。
 * 处理配置的优先级关系，提供统一的配置访问接口。
 * </p>
 * 
 * <h3>核心功能：</h3>
 * <ul>
 *   <li>配置优先级处理：注解配置优先于全局配置</li>
 *   <li>配置缓存：缓存解析后的配置，提高性能</li>
 *   <li>配置合并：合并注解配置和全局配置</li>
 *   <li>默认配置处理：提供合理的默认值</li>
 * </ul>
 * 
 * <h3>配置优先级：</h3>
 * <ol>
 *   <li>注解配置（最高优先级）</li>
 *   <li>全局YAML配置</li>
 *   <li>默认配置（最低优先级）</li>
 * </ol>
 * 
 * <h3>使用示例：</h3>
 * <pre>
 * &#064;Autowired
 * private ConfigurationResolver configurationResolver;
 * 
 * // 解析加密字段配置
 * MergedEncryptField encryptConfig = configurationResolver.resolve(encryptFieldAnnotation);
 * 
 * // 解析鉴别码配置
 * MergedIdentificationCode idCodeConfig = configurationResolver.resolve(identificationCodeAnnotation);
 * 
 * // 获取加密配置
 * DataSecurityProperties.EncryptionConfig encryptionConfig = configurationResolver.getEncryptionConfig();
 * </pre>
 * 
 * @author Cherry
 * @since 1.0.0
 * @see DataSecurityProperties
 * @see EncryptField
 * @see IdentificationCode
 */
@Slf4j
@Component
@EnableConfigurationProperties({DataSecurityProperties.class, DataSecurityRuoYiProperties.class, DataSecurityYuDaoProperties.class})
public class ConfigurationResolver {

    /**
     * 默认配置标记
     * <p>
     * 用于标识注解中的默认值，当注解属性值为该标记时，
     * 表示使用全局配置或默认配置。
     * </p>
     */
    private static final String DEFAULT_MARKER = "##DEFAULT##";

    /**
     * 数据安全配置属性
     */
    @Autowired
    private DataSecurityProperties properties;

    /**
     * MyBatis-Plus配置属性
     */
    @Autowired
    private MybatisPlusProperties mybatisPlusProperties;

    /**
     * 加密字段配置缓存
     * <p>
     * 缓存解析后的加密字段配置，避免重复解析。
     * </p>
     */
    private final Map<EncryptField, MergedEncryptField> encryptFieldCache = new ConcurrentHashMap<>();

    /**
     * 鉴别码配置缓存
     * <p>
     * 缓存解析后的鉴别码配置，避免重复解析。
     * </p>
     */
    private final Map<IdentificationCode, MergedIdentificationCode> identificationCodeCache = new ConcurrentHashMap<>();

    /**
     * 解析加密字段配置
     * <p>
     * 根据注解配置和全局配置，解析并合并生成最终的加密字段配置。
     * 解析结果会被缓存，以提高后续访问性能。
     * </p>
     * 
     * @param annotation 加密字段注解
     * @return 合并后的加密字段配置
     */
    public MergedEncryptField resolve(EncryptField annotation) {
        return encryptFieldCache.computeIfAbsent(annotation, this::resolveEncryptField);
    }

    /**
     * 解析鉴别码配置
     * <p>
     * 根据注解配置和全局配置，解析并合并生成最终的鉴别码配置。
     * 解析结果会被缓存，以提高后续访问性能。
     * </p>
     * 
     * @param annotation 鉴别码注解
     * @return 合并后的鉴别码配置
     */
    public MergedIdentificationCode resolve(IdentificationCode annotation) {
        return identificationCodeCache.computeIfAbsent(annotation, this::resolveIdentificationCode);
    }

    /**
     * 获取全局配置
     * <p>
     * 获取MyBatis-Plus的全局配置信息。
     * </p>
     * 
     * @return MyBatis-Plus全局配置
     */
    public GlobalConfig getGlobalConfig() {
        return mybatisPlusProperties.getGlobalConfig();
    }

    /**
     * 获取全局插入策略
     * <p>
     * 获取MyBatis-Plus的全局字段插入策略。
     * </p>
     * 
     * @return 全局插入策略
     */
    public FieldStrategy getGlobalInsertStrategy() {
        GlobalConfig.DbConfig dbConfig = mybatisPlusProperties.getGlobalConfig().getDbConfig();
        return dbConfig.getInsertStrategy();
    }

    /**
     * 获取全局更新策略
     * <p>
     * 获取MyBatis-Plus的全局字段更新策略。
     * </p>
     * 
     * @return 全局更新策略
     */
    public FieldStrategy getGlobalUpdateStrategy() {
        GlobalConfig.DbConfig dbConfig = mybatisPlusProperties.getGlobalConfig().getDbConfig();
        return dbConfig.getUpdateStrategy();
    }

    /**
     * 获取加密配置
     * <p>
     * 获取数据安全插件的加密配置信息。
     * </p>
     * 
     * @return 加密配置
     */
    public DataSecurityProperties.EncryptionConfig getEncryptionConfig() {
        return properties.getEncryption();
    }

    /**
     * 获取鉴别码配置
     * <p>
     * 获取数据安全插件的鉴别码配置信息。
     * </p>
     * 
     * @return 鉴别码配置
     */
    public DataSecurityProperties.IdentificationConfig getIdentificationConfig() {
        return properties.getIdentification();
    }

    /**
     * 清除配置缓存
     * <p>
     * 清除所有缓存的配置信息，下次访问时重新解析。
     * 适用于配置动态更新的场景。
     * </p>
     */
    public void clearCache() {
        encryptFieldCache.clear();
        identificationCodeCache.clear();
        log.info("配置缓存已清除");
    }

    /**
     * 解析加密字段配置
     * <p>
     * 合并注解配置和全局配置，生成最终的加密字段配置。
     * 配置优先级：注解配置 > 全局配置 > 默认配置
     * </p>
     * 
     * @param annotation 加密字段注解
     * @return 合并后的加密字段配置
     */
    private MergedEncryptField resolveEncryptField(EncryptField annotation) {
        MergedEncryptField config = new MergedEncryptField();
        DataSecurityProperties.EncryptionConfig globalConfig = properties.getEncryption();

        config.setAlgorithm(globalConfig.getAlgorithm());
        config.setKeyId(globalConfig.getKeyId());
        config.setMode(globalConfig.getMode());
        config.setPadding(globalConfig.getPadding());
        config.setDesensitizeInLog(annotation.desensitizeInLog());
        config.setDesensitizeRule(annotation.desensitizeRule());
        config.setStrategy(globalConfig.getStrategy());
        config.setKeyProvider(globalConfig.getKeyProvider());

        log.debug("解析加密字段配置: algorithm={}, mode={}, keyProvider={}",
                config.getAlgorithm(), config.getMode(), config.getKeyProvider());

        return config;
    }

    /**
     * 解析鉴别码配置
     * <p>
     * 合并注解配置和全局配置，生成最终的鉴别码配置。
     * 配置优先级：注解配置 > 全局配置 > 默认配置
     * </p>
     * 
     * @param annotation 鉴别码注解
     * @return 合并后的鉴别码配置
     */
    private MergedIdentificationCode resolveIdentificationCode(IdentificationCode annotation) {
        MergedIdentificationCode config = new MergedIdentificationCode();
        DataSecurityProperties.IdentificationConfig globalConfig = properties.getIdentification();

        config.setContentField(resolveString(annotation.contentField(), globalConfig.getContentField(), ""));
        config.setCodeField(resolveString(annotation.codeField(), globalConfig.getCodeField(), "identification_code"));

        if (annotation.includeFields().length > 0) {
            config.setIncludeFields(new HashSet<>(Arrays.asList(annotation.includeFields())));
        } else {
            config.setIncludeFields(new HashSet<>());
        }

        Set<String> excludeFields = new HashSet<>();
        if (annotation.excludeFields().length > 0) {
            excludeFields.addAll(Arrays.asList(annotation.excludeFields()));
        } else if (globalConfig.getExcludeFields() != null) {
            excludeFields.addAll(globalConfig.getExcludeFields());
        }
        config.setExcludeFields(excludeFields);

        config.setAlgorithm(resolveString(annotation.algorithm(), globalConfig.getAlgorithm(), "SHA-256"));
        config.setReturnCheckResult(annotation.returnCheckResult());
        config.setCheckResultField(resolveString(annotation.checkResultField(), globalConfig.getCheckResultField(), "identificationValid"));
        config.setStrategy(resolveString(annotation.strategy(), globalConfig.getStrategy(), ""));
        config.setDataCollector(resolveString(annotation.dataCollector(), globalConfig.getDataCollector(), ""));
        config.setEnabled(globalConfig.isEnabled());

        log.debug("解析鉴别码配置: algorithm={}, contentField={}, codeField={}",
                config.getAlgorithm(), config.getContentField(), config.getCodeField());

        return config;
    }

    /**
     * 解析字符串配置
     * <p>
     * 根据优先级解析字符串配置：
     * <ol>
     *   <li>如果注解值不为空且不是默认标记，使用注解值</li>
     *   <li>如果全局配置值不为空，使用全局配置值</li>
     *   <li>否则使用默认值</li>
     * </ol>
     * </p>
     * 
     * @param annotationValue 注解配置值
     * @param globalValue 全局配置值
     * @param defaultValue 默认值
     * @return 解析后的配置值
     */
    private String resolveString(String annotationValue, String globalValue, String defaultValue) {
        if (StringUtils.isNotBlank(annotationValue) && !DEFAULT_MARKER.equals(annotationValue)) {
            return annotationValue;
        }
        if (StringUtils.isNotBlank(globalValue)) {
            return globalValue;
        }
        return defaultValue;
    }

    /**
     * 合并后的鉴别码配置
     * <p>
     * 包含鉴别码生成和验证所需的所有配置信息。
     * </p>
     */
    @Setter
    @Getter
    public static class MergedIdentificationCode {

        /**
         * 鉴别码内容字段名
         */
        private String contentField;

        /**
         * 鉴别码字段名
         */
        private String codeField;

        /**
         * 参与鉴别码计算的字段集合
         */
        private Set<String> includeFields;

        /**
         * 不参与鉴别码计算的字段集合
         */
        private Set<String> excludeFields;

        /**
         * 鉴别码算法
         */
        private String algorithm;

        /**
         * 是否返回校验结果
         */
        private boolean returnCheckResult;

        /**
         * 校验结果字段名
         */
        private String checkResultField;

        /**
         * 鉴别码策略
         */
        private String strategy;

        /**
         * 数据收集器
         */
        private String dataCollector;

        /**
         * 是否启用鉴别码功能
         */
        private boolean enabled;
    }

    /**
     * 合并后的加密字段配置
     * <p>
     * 包含数据加密所需的所有配置信息。
     * </p>
     */
    @Setter
    @Getter
    public static class MergedEncryptField {

        /**
         * 加密算法
         */
        private String algorithm;

        /**
         * 密钥ID
         */
        private String keyId;

        /**
         * 加密模式
         */
        private String mode;

        /**
         * 填充方式
         */
        private String padding;

        /**
         * 是否在日志中脱敏
         */
        private boolean desensitizeInLog;

        /**
         * 脱敏规则
         */
        private String desensitizeRule;

        /**
         * 加密策略
         */
        private String strategy;

        /**
         * 密钥提供器
         */
        private String keyProvider;
    }
}
