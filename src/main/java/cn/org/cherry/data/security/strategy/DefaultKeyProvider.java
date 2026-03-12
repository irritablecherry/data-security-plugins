package cn.org.cherry.data.security.strategy;

import cn.org.cherry.data.security.config.DataSecurityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 默认密钥提供器
 * <p>
 * 从配置文件中加载密钥，支持多种加密算法（AES、SM4、DES、RSA）。
 * 支持自定义密钥 ID 和默认密钥配置。
 * </p>
 *
 * <h3>密钥配置优先级：</h3>
 * <ol>
 *   <li>自定义密钥（通过 keyId 指定）</li>
 *   <li>算法默认密钥（通过 algorithm 指定）</li>
 * </ol>
 *
 * <h3>支持的算法：</h3>
 * <ul>
 *   <li>AES：高级加密标准，密钥长度 16 字节</li>
 *   <li>SM4：国密算法，密钥长度 16 字节</li>
 *   <li>DES：数据加密标准，密钥长度 8 字节</li>
 *   <li>RSA：非对称加密算法，使用公钥</li>
 * </ul>
 *
 * <h3>使用示例：</h3>
 * <pre>
 * // 获取默认 AES 密钥
 * Key aesKey = keyProvider.getKey(null, "AES");
 *
 * // 获取自定义密钥
 * Key customKey = keyProvider.getKey("myCustomKey", "AES");
 *
 * // 获取 RSA 公钥
 * Key rsaKey = keyProvider.getKey(null, "RSA");
 * </pre>
 *
 * <h3>配置示例（application.yml）：</h3>
 * <pre>
 * data-security:
 *   encryption:
 *     keys:
 *       aes: "0123456789ABCDEF0123456789ABCDEF"
 *       sm4: "0123456789ABCDEF0123456789ABCDEF"
 *       des: "0123456789ABCDEF"
 *       rsa: "Base64EncodedPublicKey"
 *       custom-keys:
 *         myCustomKey: "CustomKeyValue"
 * </pre>
 *
 * @author Cherry
 * @since 1.0.0
 * @see KeyProvider
 * @see DataSecurityProperties
 */
@Slf4j
@Component("defaultKeyProvider")
public class DefaultKeyProvider implements KeyProvider {

    /**
     * AES 算法密钥长度（字节）
     */
    private static final int AES_KEY_LENGTH = 16;

    /**
     * SM4 算法密钥长度（字节）
     */
    private static final int SM4_KEY_LENGTH = 16;

    /**
     * DES 算法密钥长度（字节）
     */
    private static final int DES_KEY_LENGTH = 8;

    /**
     * AES 算法名称
     */
    private static final String ALGORITHM_AES = "AES";

    /**
     * SM4 算法名称
     */
    private static final String ALGORITHM_SM4 = "SM4";

    /**
     * DES 算法名称
     */
    private static final String ALGORITHM_DES = "DES";

    /**
     * RSA 算法名称
     */
    private static final String ALGORITHM_RSA = "RSA";

    /**
     * 数据安全配置属性
     */
    @Autowired
    private DataSecurityProperties properties;

    /**
     * 获取密钥
     * <p>
     * 根据密钥 ID 和算法名称获取对应的密钥对象。
     * 如果指定了密钥 ID，优先从自定义密钥中获取；
     * 否则从算法默认密钥中获取。
     * </p>
     *
     * @param keyId 密钥 ID，用于获取自定义密钥，可为 null 或空字符串
     * @param algorithm 加密算法，如 "AES"、"SM4"、"DES"、"RSA"
     * @return 密钥对象
     * @throws IllegalArgumentException 如果密钥不存在或算法不支持
     * @throws RuntimeException 密钥生成失败时抛出
     */
    @Override
    public Key getKey(String keyId, String algorithm) {
        log.debug("获取密钥：keyId={}, algorithm={}", keyId, algorithm);

        String keyValue = getKeyValue(keyId, algorithm);
        if (keyValue == null || keyValue.isEmpty()) {
            log.error("密钥不存在：algorithm={}, keyId={}", algorithm, keyId);
            throw new IllegalArgumentException("密钥不存在：algorithm=" + algorithm + ", keyId=" + keyId);
        }

        Key key = generateKey(keyValue, algorithm);
        log.debug("密钥获取成功：algorithm={}", algorithm);

        return key;
    }

    /**
     * 判断是否支持指定的加密算法
     *
     * @param algorithm 算法名称
     * @return 如果支持返回 true，否则返回 false
     */
    @Override
    public boolean supports(String algorithm) {
        return ALGORITHM_AES.equalsIgnoreCase(algorithm) ||
                ALGORITHM_SM4.equalsIgnoreCase(algorithm) ||
                ALGORITHM_DES.equalsIgnoreCase(algorithm) ||
                ALGORITHM_RSA.equalsIgnoreCase(algorithm);
    }

    /**
     * 获取密钥值
     * <p>
     * 根据密钥 ID 和算法名称获取密钥字符串值。
     * 优先从自定义密钥中获取，如果不存在则从算法默认密钥中获取。
     * </p>
     *
     * @param keyId 密钥 ID
     * @param algorithm 加密算法
     * @return 密钥字符串值，如果不存在返回 null
     */
    private String getKeyValue(String keyId, String algorithm) {
        DataSecurityProperties.KeyConfig keyConfig = properties.getEncryption().getKeys();

        // 优先从自定义密钥中获取
        if (keyId != null && !keyId.isEmpty()) {
            String customKey = keyConfig.getCustomKey(keyId);
            if (customKey != null && !customKey.isEmpty()) {
                log.debug("使用自定义密钥：keyId={}", keyId);
                return customKey;
            }
            log.warn("自定义密钥不存在：keyId={}, 尝试使用默认密钥", keyId);
        }

        // 从算法默认密钥中获取
        String keyValue = getDefaultKeyValue(keyConfig, algorithm);
        if (keyValue != null && !keyValue.isEmpty()) {
            log.debug("使用默认密钥：algorithm={}", algorithm);
        }

        return keyValue;
    }

    /**
     * 获取算法默认密钥值
     *
     * @param keyConfig 密钥配置
     * @param algorithm 加密算法
     * @return 默认密钥值，如果不支持该算法返回 null
     */
    private String getDefaultKeyValue(DataSecurityProperties.KeyConfig keyConfig, String algorithm) {
        switch (algorithm.toUpperCase()) {
            case "AES":
                return keyConfig.getAes();
            case "SM4":
                return keyConfig.getSm4();
            case "DES":
                return keyConfig.getDes();
            case "RSA":
                return keyConfig.getRsa();
            default:
                log.warn("不支持的加密算法：{}", algorithm);
                return null;
        }
    }

    /**
     * 生成密钥对象
     * <p>
     * 根据密钥字符串值和算法名称生成对应的密钥对象。
     * 对于对称加密算法（AES、SM4、DES），使用 SecretKeySpec 生成密钥；
     * 对于非对称加密算法（RSA），使用 X509EncodedKeySpec 生成公钥。
     * </p>
     *
     * @param keyValue 密钥字符串值
     * @param algorithm 加密算法
     * @return 密钥对象
     * @throws IllegalArgumentException 如果算法不支持
     * @throws RuntimeException 密钥生成失败时抛出
     */
    private Key generateKey(String keyValue, String algorithm) {
        try {
            switch (algorithm.toUpperCase()) {
                case "AES":
                    return generateSymmetricKey(keyValue, ALGORITHM_AES, AES_KEY_LENGTH);
                case "SM4":
                    return generateSymmetricKey(keyValue, ALGORITHM_SM4, SM4_KEY_LENGTH);
                case "DES":
                    return generateSymmetricKey(keyValue, ALGORITHM_DES, DES_KEY_LENGTH);
                case "RSA":
                    return generateRsaPublicKey(keyValue);
                default:
                    throw new IllegalArgumentException("不支持的加密算法：" + algorithm);
            }
        } catch (Exception e) {
            log.error("密钥生成失败：algorithm={}", algorithm, e);
            throw new RuntimeException("密钥生成失败：algorithm=" + algorithm, e);
        }
    }

    /**
     * 生成对称加密密钥
     * <p>
     * 生成密钥前会校验密钥强度，确保密钥长度符合要求。
     * </p>
     *
     * @param keyValue 密钥字符串值
     * @param algorithm 算法名称
     * @param keyLength 密钥长度（字节）
     * @return 对称加密密钥
     * @throws IllegalArgumentException 如果密钥长度不足
     */
    private Key generateSymmetricKey(String keyValue, String algorithm, int keyLength) {
        // 校验密钥强度
        validateKeyStrength(keyValue, algorithm, keyLength);
        
        byte[] keyBytes = keyValue.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes, 0, keyLength, algorithm);
    }

    /**
     * 生成 RSA 公钥
     *
     * @param keyValue Base64 编码的公钥字符串
     * @return RSA 公钥
     * @throws Exception 公钥生成失败时抛出
     */
    private Key generateRsaPublicKey(String keyValue) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyValue);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 校验密钥强度
     * <p>
     * 检查密钥长度是否满足算法要求，避免使用弱密钥。
     * </p>
     *
     * @param keyValue 密钥字符串值
     * @param algorithm 算法名称
     * @param requiredLength 要求的密钥长度（字节）
     * @throws IllegalArgumentException 如果密钥长度不足
     */
    private void validateKeyStrength(String keyValue, String algorithm, int requiredLength) {
        if (keyValue == null || keyValue.isEmpty()) {
            throw new IllegalArgumentException("密钥不能为空：algorithm=" + algorithm);
        }
        
        // 检查密钥长度（按字节计算）
        byte[] keyBytes = keyValue.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < requiredLength) {
            throw new IllegalArgumentException(
                    String.format("密钥长度不足：algorithm=%s, 要求长度=%d 字节，实际长度=%d 字节", 
                            algorithm, requiredLength, keyBytes.length));
        }
        
        // 对于 AES-256，建议使用 32 字节密钥
        if (ALGORITHM_AES.equalsIgnoreCase(algorithm) && keyBytes.length < 32) {
            log.warn("⚠️  安全建议：AES 密钥长度为 {} 字节，建议使用 32 字节 (AES-256) 以增强安全性", keyBytes.length);
        }
        
        // 检查弱密钥模式（如全 0、全 1、连续数字等）
        if (isWeakKeyPattern(keyValue)) {
            log.warn("⚠️  安全警告：检测到弱密钥模式（如连续数字、重复字符等），建议使用强随机密钥！");
        }
    }

    /**
     * 检查是否为弱密钥模式
     *
     * @param keyValue 密钥字符串
     * @return 如果是弱密钥模式返回 true
     */
    private boolean isWeakKeyPattern(String keyValue) {
        // 检查是否为连续数字
        if (keyValue.matches("^[0-9]+$")) {
            return true;
        }
        
        // 检查是否为连续相同字符
        if (keyValue.matches("^(.)\\1*$")) {
            return true;
        }
        
        // 检查是否为常见弱密钥（如全 0、全 1、字母表顺序等）
        String lowerKey = keyValue.toLowerCase();
        return "0000000000000000".equals(lowerKey) ||
               "ffffffffffffffff".equals(lowerKey) ||
               "abcdef0123456789abcdef0123456789".equals(lowerKey);
    }
}
