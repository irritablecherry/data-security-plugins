package cn.org.cherry.data.security.config;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 数据安全插件配置属性
 * <p>
 * 提供数据安全插件的所有配置属性，支持通过 application.yml 或 application.properties 进行配置。
 * 配置前缀为：data-security
 * </p>
 *
 * <h3>配置示例：</h3>
 * <pre>
 * data-security:
 *   enabled: true
 *   identification:
 *     enabled: true
 *     code-field: "identification_code"
 *     algorithm: "SHA-256"
 *   encryption:
 *     enabled: true
 *     algorithm: "AES"
 *     mode: "CBC"
 *     padding: "PKCS5Padding"
 *     keys:
 *       aes: "0123456789ABCDEF0123456789ABCDEF"
 *       sm4: "0123456789ABCDEF0123456789ABCDEF"
 *       des: "0123456789ABCDEF"
 *       rsa: "Base64EncodedPublicKey"
 * </pre>
 *
 * <h3>配置说明：</h3>
 * <ul>
 *   <li>enabled: 是否启用数据安全插件</li>
 *   <li>identification: 鉴别码相关配置</li>
 *   <li>encryption: 数据加密相关配置</li>
 *   <li>autoCreate: 自动建表相关配置</li>
 *   <li>strategy: 策略相关配置</li>
 * </ul>
 *
 * @author Cherry
 * @since 1.0.0
 * @see ConfigurationResolver
 */
@Slf4j
@Setter
@Getter
@ConfigurationProperties(prefix = "data-security")
public class DataSecurityProperties {

    /**
     * 是否启用数据安全插件
     * <p>
     * 默认值为 true，表示启用插件。
     * </p>
     */
    private boolean enabled = true;

    /**
     * 鉴别码配置
     * <p>
     * 包含鉴别码相关的所有配置项。
     * </p>
     */
    private IdentificationConfig identification = new IdentificationConfig();

    /**
     * 加密配置
     * <p>
     * 包含数据加密相关的所有配置项。
     * </p>
     */
    private EncryptionConfig encryption = new EncryptionConfig();

    /**
     * 自动建表配置
     * <p>
     * 包含自动创建鉴别码和加密字段的相关配置。
     * </p>
     */
    private AutoCreateConfig autoCreate = new AutoCreateConfig();

    /**
     * 若依多租户配置
     */
    private RuoYiConfig ruoYi = new RuoYiConfig();

    /**
     * 芋道多租户配置
     */
    private YuDaoConfig yuDao = new YuDaoConfig();

    /**
     * 鉴别码配置类
     * <p>
     * 包含鉴别码算法、字段名等配置。
     * </p>
     */
    @Setter
    @Getter
    public static class IdentificationConfig {

        /**
         * 是否启用鉴别码
         * <p>
         * 默认值为 true。
         * </p>
         */
        private boolean enabled = true;

        /**
         * 鉴别码算法
         * <p>
         * 支持的算法：SHA-256、SM3。
         * 默认值为"SHA-256"。
         * </p>
         */
        private String algorithm = "SHA-256";

        /**
         * 鉴别码字段名
         * <p>
         * 默认值为"identification_code"。
         * </p>
         */
        private String codeField = "identification_code";

        /**
         * 鉴别内容字段名
         * <p>
         * 默认值为空，表示自动识别。
         * </p>
         */
        private String contentField;

        /**
         * 鉴别结果字段名
         * <p>
         * 默认值为"check_result"。
         * </p>
         */
        private String checkResultField = "check_result";

        /**
         * 是否启用内容日志
         * <p>
         * 如果为 true，将在日志中记录鉴别码原始数据（脱敏后）。
         * 默认值为 false。
         * </p>
         */
        private boolean contentLog = false;

        /**
         * 排除字段列表
         * <p>
         * 配置此列表后，列表中的字段将不会被包含在鉴别码计算中。
         * </p>
         */
        private Set<String> excludeFields = new HashSet<>();

        /**
         * 默认脱敏规则
         * <p>
         * 脱敏规则格式：保留前 N 位@保留后 M 位，如"3@4"表示保留前 3 位和后 4 位。
         * 默认值为"3@4"。
         * </p>
         */
        private String defaultDesensitizeRule = "3@4";

        /**
         * 默认鉴别码策略
         * <p>
         * 鉴别码策略的 Spring Bean 名称。
         * 默认值为"defaultIdentificationCodeStrategy"。
         * </p>
         */
        private String strategy = "defaultIdentificationCodeStrategy";

        /**
         * 默认数据收集器
         * <p>
         * 数据收集器的 Spring Bean 名称。
         * 默认值为"defaultDataCollector"。
         * </p>
         */
        private String dataCollector = "defaultDataCollector";
    }

    /**
     * 加密配置类
     * <p>
     * 包含加密算法、模式、填充方式等配置。
     * </p>
     */
    @Setter
    @Getter
    public static class EncryptionConfig {

        /**
         * 是否启用加密
         * <p>
         * 默认值为 true。
         * </p>
         */
        private boolean enabled = true;

        /**
         * 加密算法
         * <p>
         * 支持的算法：AES、SM4、DES、RSA。
         * 默认值为"AES"。
         * </p>
         */
        private String algorithm = "AES";

        /**
         * 加密模式
         * <p>
         * 支持的模式：CBC、GCM。
         * 默认值为"CBC"。
         * </p>
         */
        private String mode = "CBC";

        /**
         * 填充方式
         * <p>
         * 支持的填充：PKCS5Padding、NoPadding。
         * 默认值为"PKCS5Padding"。
         * </p>
         */
        private String padding = "PKCS5Padding";

        /**
         * 密钥 ID
         * <p>
         * 用于指定使用哪个密钥进行加密。
         * 默认值为空，使用算法对应的默认密钥。
         * </p>
         */
        private String keyId;


        /**
         * 默认加密策略
         * <p>
         * 加密策略的 Spring Bean 名称。
         * 默认值为"defaultEncryptionStrategy"。
         * </p>
         */
        private String strategy = "defaultEncryptionStrategy";

        /**
         * 默认密钥提供器
         * <p>
         * 密钥提供器的 Spring Bean 名称。
         * 默认值为"defaultKeyProvider"。
         * </p>
         */
        private String keyProvider = "defaultKeyProvider";

        /**
         * 密钥配置
         * <p>
         * 包含各种算法的密钥配置和自定义密钥配置。
         * </p>
         */
        private KeyConfig keys = new KeyConfig();

        /**
         * 支持的加密算法列表
         */
        private Set<String> supportedAlgorithms = new HashSet<>();

        /**
         * 初始化支持的算法
         */
        public EncryptionConfig() {
            supportedAlgorithms.add("AES");
            supportedAlgorithms.add("SM4");
            supportedAlgorithms.add("RSA");
            supportedAlgorithms.add("DES");
        }
    }

    /**
     * 密钥配置类
     * <p>
     * 包含各种加密算法的密钥配置和自定义密钥配置。
     * 支持从环境变量加载密钥，优先使用环境变量，其次使用配置文件。
     * </p>
     */
    @Setter
    @Getter
    public static class KeyConfig {

        /**
         * AES 算法密钥
         * <p>
         * AES 算法密钥，长度必须为 16 字节（128 位）。
         * 默认值为"0123456789ABCDEF0123456789ABCDEF"。
         * </p>
         */
        private String aes = "0123456789ABCDEF0123456789ABCDEF";

        /**
         * SM4 算法密钥
         * <p>
         * SM4 算法密钥，长度必须为 16 字节（128 位）。
         * 默认值为"0123456789ABCDEF0123456789ABCDEF"。
         * </p>
         */
        private String sm4 = "0123456789ABCDEF0123456789ABCDEF";

        /**
         * DES 算法密钥
         * <p>
         * DES 算法密钥，长度必须为 8 字节（64 位）。
         * 默认值为"0123456789ABCDEF"。
         * </p>
         */
        private String des = "0123456789ABCDEF";

        /**
         * RSA 算法公钥
         * <p>
         * RSA 算法公钥，使用 Base64 编码。
         * 默认值为空字符串。
         * </p>
         */
        private String rsa = "";

        /**
         * 自定义密钥映射
         * <p>
         * key 为密钥 ID，value 为密钥值。
         * 用于支持多密钥场景。
         * </p>
         */
        private Map<String, String> customKeys = new HashMap<>();

        /**
         * 默认密钥标记 - 用于检测是否使用默认密钥
         */
        private static final String DEFAULT_AES_KEY = "0123456789ABCDEF0123456789ABCDEF";
        private static final String DEFAULT_SM4_KEY = "0123456789ABCDEF0123456789ABCDEF";
        private static final String DEFAULT_DES_KEY = "0123456789ABCDEF";

        /**
         * 初始化密钥配置
         * <p>
         * 尝试从环境变量加载密钥，如果环境变量不存在则使用默认值。
         * 如果检测到使用默认密钥，将记录警告日志。
         * </p>
         */
        public KeyConfig() {
            // 尝试从环境变量加载密钥
            String envAesKey = System.getenv("DATA_SECURITY_AES_KEY");
            String envSm4Key = System.getenv("DATA_SECURITY_SM4_KEY");
            String envDesKey = System.getenv("DATA_SECURITY_DES_KEY");

            // 如果环境变量存在，使用环境变量；否则使用默认值
            if (envAesKey != null && !envAesKey.isEmpty()) {
                this.aes = envAesKey;
            } else {
                log.warn("⚠️  安全警告：未配置 DATA_SECURITY_AES_KEY 环境变量，使用默认 AES 密钥！");
                log.warn("   生产环境必须通过环境变量或配置文件设置独立密钥，否则存在严重安全风险！");
            }

            if (envSm4Key != null && !envSm4Key.isEmpty()) {
                this.sm4 = envSm4Key;
            } else {
                log.warn("⚠️  安全警告：未配置 DATA_SECURITY_SM4_KEY 环境变量，使用默认 SM4 密钥！");
                log.warn("   生产环境必须通过环境变量或配置文件设置独立密钥，否则存在严重安全风险！");
            }

            if (envDesKey != null && !envDesKey.isEmpty()) {
                this.des = envDesKey;
            } else {
                log.warn("⚠️  安全警告：未配置 DATA_SECURITY_DES_KEY 环境变量，使用默认 DES 密钥！");
                log.warn("   生产环境必须通过环境变量或配置文件设置独立密钥，否则存在严重安全风险！");
            }
        }

        /**
         * 根据密钥 ID 获取自定义密钥
         *
         * @param keyId 密钥 ID
         * @return 密钥值，如果不存在返回 null
         */
        public String getCustomKey(String keyId) {
            return customKeys.get(keyId);
        }

        /**
         * 添加自定义密钥
         *
         * @param keyId 密钥 ID
         * @param keyValue 密钥值
         */
        public void addCustomKey(String keyId, String keyValue) {
            customKeys.put(keyId, keyValue);
        }

        /**
         * 检查是否使用默认密钥
         *
         * @param algorithm 算法名称
         * @return 如果使用默认密钥返回 true
         */
        public boolean isUsingDefaultKey(String algorithm) {
            if (algorithm == null) {
                return false;
            }
            String upperAlgorithm = algorithm.toUpperCase();
            if ("AES".equals(upperAlgorithm)) {
                return DEFAULT_AES_KEY.equals(this.aes);
            } else if ("SM4".equals(upperAlgorithm)) {
                return DEFAULT_SM4_KEY.equals(this.sm4);
            } else if ("DES".equals(upperAlgorithm)) {
                return DEFAULT_DES_KEY.equals(this.des);
            }
            return false;
        }
    }

    /**
     * 自动建表配置类
     * <p>
     * 包含自动创建鉴别码和加密字段的相关配置。
     * </p>
     */
    @Setter
    @Getter
    public static class AutoCreateConfig {

        /**
         * 是否自动创建字段
         * <p>
         * 如果为 true，启动时会自动创建鉴别码和加密字段。
         * 默认值为 true。
         * </p>
         */
        private boolean enabled = true;

        /**
         * 是否自动处理数据
         * <p>
         * 如果为 true，启动时会自动处理已有数据。
         * 默认值为 true。
         * </p>
         */
        private boolean autoHandleDataEnable = true;

        /**
         * 是否异步处理数据
         * <p>
         * 如果为 true，启动时异步处理数据。
         * 默认值为 false。
         * </p>
         */
        private boolean autoHandleDataAsync = false;

        /**
         * 批量处理大小
         * <p>
         * 每次批量处理的记录数。
         * 默认值为 1000。
         * </p>
         */
        private int batchSize = 1000;
    }

    /**
     * 若依多租户配置类
     */
    @Setter
    @Getter
    public static class RuoYiConfig {

        /**
         * 是否启用若依多租户
         * <p>
         * 默认值为 false。
         * </p>
         */
        private boolean enable = false;

        /**
         * 忽略的表列表
         * <p>
         * 配置此列表后，列表中的表将不会被多租户检查。
         * </p>
         */
        private Set<String> ignoreTables = new HashSet<>();
    }

    /**
     * 御道多租户配置类
     */
    @Setter
    @Getter
    public static class YuDaoConfig {

        /**
         * 是否启用御道多租户
         * <p>
         * 默认值为 false。
         * </p>
         */
        private boolean enable = false;

        /**
         * 忽略的表列表
         * <p>
         * 配置此列表后，列表中的表将不会被多租户检查。
         * </p>
         */
        private Set<String> ignoreTables = new HashSet<>();
    }
}
