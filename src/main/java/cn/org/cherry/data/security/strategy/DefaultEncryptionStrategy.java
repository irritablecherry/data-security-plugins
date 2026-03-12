package cn.org.cherry.data.security.strategy;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.config.DataSecurityProperties;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 默认加密策略实现
 * <p>
 * 提供基于对称加密算法（AES、SM4、DES）和非对称加密算法（RSA）的数据加密解密功能。
 * 支持多种加密模式（CBC、GCM 等）和填充方式（PKCS5Padding 等）。
 * </p>
 *
 * <h3>特性：</h3>
 * <ul>
 *   <li>支持多种加密算法：AES、SM4、DES、RSA</li>
 *   <li>支持多种加密模式：CBC、GCM 等</li>
 *   <li>自动生成和管理初始化向量 (IV)</li>
 *   <li>密钥缓存机制，提高性能</li>
 *   <li>Cipher 实例线程本地缓存，减少对象创建开销</li>
 *   <li>加密数据自动添加标识前缀，便于识别</li>
 * </ul>
 *
 * <h3>使用示例：</h3>
 * <pre>
 * &#064;Autowired
 * private EncryptionStrategy encryptionStrategy;
 *
 * // 加密
 * String ciphertext = encryptionStrategy.encrypt("敏感数据");
 *
 * // 解密
 * String plaintext = encryptionStrategy.decrypt(ciphertext);
 *
 * // 判断是否已加密
 * boolean encrypted = encryptionStrategy.isEncrypted(ciphertext);
 * </pre>
 *
 * @author Cherry
 * @since 1.0.0
 * @see EncryptionStrategy
 * @see KeyProvider
 */
@Slf4j
@Component
public class DefaultEncryptionStrategy implements EncryptionStrategy {

    /**
     * 加密数据标识前缀
     */
    private static final String ENCRYPTION_PREFIX = "ds:enc:";

    /**
     * 安全随机数生成器
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * GCM 模式 IV 长度（12 字节）
     */
    private static final int GCM_IV_LENGTH = 12;

    /**
     * 默认 IV 长度（16 字节）
     */
    private static final int DEFAULT_IV_LENGTH = 16;

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
     * GCM 加密模式
     */
    private static final String MODE_GCM = "GCM";

    /**
     * CBC 加密模式
     */
    private static final String MODE_CBC = "CBC";

    /**
     * 密钥缓存
     */
    private static final Map<String, Key> KEY_CACHE = new ConcurrentHashMap<>();

    /**
     * Cipher 实例线程本地缓存 - 每个线程维护自己的 Cipher 实例
     * 因为 Cipher 不是线程安全的，不能使用共享缓存
     */
    private static final ThreadLocal<ConcurrentMap<String, Cipher>> CIPHER_THREAD_LOCAL =
            ThreadLocal.withInitial(ConcurrentHashMap::new);

    /**
     * 转换字符串缓存
     */
    private static final Map<String, String> TRANSFORMATION_CACHE = new ConcurrentHashMap<>();

    /**
     * 策略管理器
     */
    @Autowired
    @Lazy
    private StrategyManager strategyManager;

    /**
     * 配置解析器
     */
    @Autowired
    private ConfigurationResolver configurationResolver;

    /**
     * 加密明文数据
     * <p>
     * 加密流程：
     * <ol>
     *   <li>获取加密配置（算法、密钥 ID、模式、填充方式）</li>
     *   <li>获取或生成密钥</li>
     *   <li>生成随机初始化向量 (IV)</li>
     *   <li>执行加密操作</li>
     *   <li>将 IV 和密文组合后进行 Base64 编码</li>
     *   <li>添加加密标识前缀</li>
     * </ol>
     * </p>
     *
     * @param plaintext 明文数据
     * @return 加密后的密文，格式为 "ds:enc:Base64(IV+ 密文)"
     * @throws RuntimeException 加密失败时抛出
     */
    @Override
    public String encrypt(String plaintext) {
        if (StringUtils.isBlank(plaintext)) {
            return plaintext;
        }

        try {
            DataSecurityProperties.EncryptionConfig config = configurationResolver.getEncryptionConfig();
            String algorithm = config.getAlgorithm();
            String keyId = config.getKeyId();

            Key key = getKey(keyId, algorithm);

            byte[] iv = generateIV(config.getMode());
            String transformation = getTransformation(algorithm, config.getMode(), config.getPadding());

            Cipher cipher = getCipher(transformation, Cipher.ENCRYPT_MODE, key, iv, config.getMode(), algorithm);

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            String encryptedBase64 = encodeWithIV(iv, encrypted);

            log.debug("数据加密成功：algorithm={}, mode={}", algorithm, config.getMode());
            return ENCRYPTION_PREFIX + encryptedBase64;

        } catch (Exception e) {
            log.error("数据加密失败：plaintext={}", maskSensitiveData(plaintext), e);
            throw new RuntimeException("数据加密失败", e);
        }
    }

    /**
     * 解密密文数据
     * <p>
     * 解密流程：
     * <ol>
     *   <li>验证并移除加密标识前缀</li>
     *   <li>获取加密配置（算法、密钥 ID、模式、填充方式）</li>
     *   <li>获取密钥</li>
     *   <li>从密文中提取 IV 和加密数据</li>
     *   <li>执行解密操作</li>
     * </ol>
     * </p>
     *
     * @param ciphertext 密文数据
     * @return 解密后的明文
     * @throws RuntimeException 解密失败时抛出
     */
    @Override
    public String decrypt(String ciphertext) {
        if (StringUtils.isBlank(ciphertext) || !ciphertext.startsWith(ENCRYPTION_PREFIX)) {
            return ciphertext;
        }

        try {
            String encryptedText = ciphertext.substring(ENCRYPTION_PREFIX.length());
            DataSecurityProperties.EncryptionConfig config = configurationResolver.getEncryptionConfig();
            String algorithm = config.getAlgorithm();
            String keyId = config.getKeyId();

            Key key = getKey(keyId, algorithm);

            byte[] combined = Base64.getDecoder().decode(encryptedText);
            int ivLength = getIVLength(config.getMode());
            byte[] iv = extractIV(combined, ivLength);
            byte[] encrypted = extractCiphertext(combined, ivLength);

            String transformation = getTransformation(algorithm, config.getMode(), config.getPadding());
            Cipher cipher = getCipher(transformation, Cipher.DECRYPT_MODE, key, iv, config.getMode(), algorithm);

            byte[] decrypted = cipher.doFinal(encrypted);
            String plaintext = new String(decrypted, StandardCharsets.UTF_8);

            log.debug("数据解密成功：algorithm={}, mode={}", algorithm, config.getMode());
            return plaintext;

        } catch (Exception e) {
            log.error("数据解密失败：ciphertext={}", maskSensitiveData(ciphertext), e);
            throw new RuntimeException("数据解密失败", e);
        }
    }

    /**
     * 判断字符串是否已加密
     * <p>
     * 通过检查字符串是否以加密标识前缀开头来判断。
     * </p>
     *
     * @param text 要判断的字符串
     * @return 如果字符串已加密返回 true，否则返回 false
     */
    @Override
    public boolean isEncrypted(String text) {
        if (StringUtils.isBlank(text)) {
            return false;
        }
        return text.startsWith(ENCRYPTION_PREFIX);
    }

    /**
     * 获取加密标识前缀
     *
     * @return 加密标识前缀 "ds:enc:"
     */
    @Override
    public String getEncryptPrefix() {
        return ENCRYPTION_PREFIX;
    }

    /**
     * 获取密钥
     * <p>
     * 优先从缓存中获取，如果缓存不存在则通过密钥提供器获取并缓存。
     * </p>
     *
     * @param keyId 密钥 ID，可为空
     * @param algorithm 加密算法
     * @return 密钥对象
     */
    @Override
    public Key getKey(String keyId, String algorithm) {
        String cacheKey = buildCacheKey(keyId, algorithm);
        return KEY_CACHE.computeIfAbsent(cacheKey, k -> {
            KeyProvider provider = getKeyProvider();
            return provider.getKey(keyId, algorithm);
        });
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
     * 获取密钥提供器
     * <p>
     * 从配置中获取密钥提供器名称，如果未配置则使用默认提供器。
     * </p>
     *
     * @return 密钥提供器实例
     */
    private KeyProvider getKeyProvider() {
        DataSecurityProperties.EncryptionConfig config = configurationResolver.getEncryptionConfig();
        String providerName = config.getKeyProvider();
        if (StringUtils.isBlank(providerName)) {
            providerName = "defaultKeyProvider";
        }
        return strategyManager.getKeyProvider(providerName);
    }

    /**
     * 生成初始化向量 (IV)
     *
     * @param mode 加密模式
     * @return IV 字节数组
     */
    private byte[] generateIV(String mode) {
        int ivLength = getIVLength(mode);
        byte[] iv = new byte[ivLength];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    /**
     * 获取 IV 长度
     * <p>
     * GCM 模式使用 12 字节 IV，其他模式使用 16 字节 IV。
     * </p>
     *
     * @param mode 加密模式
     * @return IV 长度（字节数）
     */
    private int getIVLength(String mode) {
        return MODE_GCM.equalsIgnoreCase(mode) ? GCM_IV_LENGTH : DEFAULT_IV_LENGTH;
    }

    /**
     * 获取转换字符串
     * <p>
     * 格式：算法/模式/填充，例如 "AES/CBC/PKCS5Padding"
     * 使用缓存提高性能。
     * </p>
     *
     * @param algorithm 加密算法
     * @param mode 加密模式
     * @param padding 填充方式
     * @return 转换字符串
     */
    private String getTransformation(String algorithm, String mode, String padding) {
        String cacheKey = algorithm + "/" + mode + "/" + padding;
        return TRANSFORMATION_CACHE.computeIfAbsent(cacheKey, k -> algorithm + "/" + mode + "/" + padding);
    }

    /**
     * 获取 Cipher 实例
     * <p>
     * 使用 ThreadLocal 机制确保每个线程有自己的 Cipher 实例。
     * Cipher 对象不是线程安全的，因此不能使用共享缓存。
     * 对于对称加密算法（AES、SM4），根据模式使用不同的参数规范。
     * </p>
     *
     * @param transformation 转换字符串
     * @param mode 加密/解密模式
     * @param key 密钥
     * @param iv 初始化向量
     * @param encryptMode 加密模式名称
     * @param algorithm 算法名称
     * @return Cipher 实例
     * @throws Exception 获取 Cipher 实例失败时抛出
     */
    private Cipher getCipher(String transformation, int mode, Key key, byte[] iv,
                            String encryptMode, String algorithm) throws Exception {
        String cipherKey = transformation + "_" + mode;
        ConcurrentMap<String, Cipher> threadCiphers = CIPHER_THREAD_LOCAL.get();
        Cipher cipher = threadCiphers.get(cipherKey);

        if (cipher == null) {
            cipher = createAndInitCipher(transformation, mode, key, iv, encryptMode, algorithm);
            threadCiphers.put(cipherKey, cipher);
        } else {
            try {
                // 重新初始化 Cipher 以使用新的密钥和 IV
                initCipher(cipher, mode, key, iv, encryptMode, algorithm);
            } catch (Exception e) {
                // 初始化失败，创建新的 Cipher
                cipher = createAndInitCipher(transformation, mode, key, iv, encryptMode, algorithm);
                threadCiphers.put(cipherKey, cipher);
            }
        }

        return cipher;
    }

    /**
     * 创建并初始化 Cipher 实例
     *
     * @param transformation 转换字符串
     * @param mode 加密/解密模式
     * @param key 密钥
     * @param iv 初始化向量
     * @param encryptMode 加密模式名称
     * @param algorithm 算法名称
     * @return 初始化后的 Cipher 实例
     * @throws Exception 初始化失败时抛出
     */
    private Cipher createAndInitCipher(String transformation, int mode, Key key, byte[] iv,
                                       String encryptMode, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        initCipher(cipher, mode, key, iv, encryptMode, algorithm);
        return cipher;
    }

    /**
     * 初始化 Cipher
     *
     * @param cipher Cipher 实例
     * @param mode 加密/解密模式
     * @param key 密钥
     * @param iv 初始化向量
     * @param encryptMode 加密模式名称
     * @param algorithm 算法名称
     * @throws Exception 初始化失败时抛出
     */
    private void initCipher(Cipher cipher, int mode, Key key, byte[] iv,
                           String encryptMode, String algorithm) throws Exception {
        if (ALGORITHM_AES.equalsIgnoreCase(algorithm) || ALGORITHM_SM4.equalsIgnoreCase(algorithm)) {
            if (MODE_GCM.equalsIgnoreCase(encryptMode)) {
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                cipher.init(mode, key, gcmSpec);
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(mode, key, ivSpec);
            }
        } else {
            cipher.init(mode, key);
        }
    }

    /**
     * 构建缓存键
     * <p>
     * 如果指定了密钥 ID 则使用密钥 ID，否则使用算法名称。
     * </p>
     *
     * @param keyId 密钥 ID
     * @param algorithm 算法名称
     * @return 缓存键
     */
    private String buildCacheKey(String keyId, String algorithm) {
        if (StringUtils.isNotBlank(keyId)) {
            return keyId;
        }
        return "key_" + algorithm;
    }

    /**
     * 编码 IV 和密文
     * <p>
     * 将 IV 和密文组合成一个字节数组，然后进行 Base64 编码。
     * 格式：IV + 密文
     * </p>
     *
     * @param iv 初始化向量
     * @param ciphertext 密文字节数组
     * @return Base64 编码的字符串
     */
    private String encodeWithIV(byte[] iv, byte[] ciphertext) {
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * 从组合数据中提取 IV
     *
     * @param combined 组合数据（IV + 密文）
     * @param ivLength IV 长度
     * @return IV 字节数组
     */
    private byte[] extractIV(byte[] combined, int ivLength) {
        byte[] iv = new byte[ivLength];
        System.arraycopy(combined, 0, iv, 0, ivLength);
        return iv;
    }

    /**
     * 从组合数据中提取密文
     *
     * @param combined 组合数据（IV + 密文）
     * @param ivLength IV 长度
     * @return 密文字节数组
     */
    private byte[] extractCiphertext(byte[] combined, int ivLength) {
        byte[] ciphertext = new byte[combined.length - ivLength];
        System.arraycopy(combined, ivLength, ciphertext, 0, ciphertext.length);
        return ciphertext;
    }

    /**
     * 脱敏敏感数据
     * <p>
     * 用于日志输出时对敏感数据进行脱敏处理，避免泄露。
     * </p>
     *
     * @param data 原始数据
     * @return 脱敏后的数据
     */
    private String maskSensitiveData(String data) {
        if (data == null) {
            return "null";
        }
        if (data.length() <= 4) {
            return "***";
        }
        return data.substring(0, 2) + "***" + data.substring(data.length() - 2);
    }
}
