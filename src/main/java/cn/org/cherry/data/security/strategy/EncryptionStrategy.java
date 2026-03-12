package cn.org.cherry.data.security.strategy;

import java.security.Key;

/**
 * 加密策略接口
 * <p>
 * 定义数据加密解密的核心策略，允许用户自定义加密和解密逻辑。
 * 该接口提供了数据加密、解密、密钥管理和加密状态判断等核心功能。
 * </p>
 * 
 * <h3>设计目标：</h3>
 * <ul>
 *   <li>提供统一的加密解密接口</li>
 *   <li>支持多种加密算法和模式</li>
 *   <li>支持自定义密钥管理策略</li>
 *   <li>支持加密数据的识别和验证</li>
 * </ul>
 * 
 * <h3>实现要求：</h3>
 * <ul>
 *   <li>实现类应支持线程安全</li>
 *   <li>实现类应提供合理的性能优化（如缓存）</li>
 *   <li>实现类应正确处理异常情况</li>
 *   <li>实现类应提供详细的错误日志</li>
 * </ul>
 * 
 * <h3>使用示例：</h3>
 * <pre>
 * // 实现自定义加密策略
 * &#064;Component
 * public class CustomEncryptionStrategy implements EncryptionStrategy {
 *     
 *     &#064;Override
 *     public String encrypt(String plaintext) {
 *         // 自定义加密逻辑
 *         return encryptedText;
 *     }
 *     
 *     &#064;Override
 *     public String decrypt(String ciphertext) {
 *         // 自定义解密逻辑
 *         return plaintext;
 *     }
 *     
 *     // 其他方法实现...
 * }
 * 
 * // 使用加密策略
 * &#064;Autowired
 * private EncryptionStrategy encryptionStrategy;
 * 
 * public void processData() {
 *     String plaintext = "敏感数据";
 *     
 *     // 加密
 *     String ciphertext = encryptionStrategy.encrypt(plaintext);
 *     
 *     // 判断是否已加密
 *     if (encryptionStrategy.isEncrypted(ciphertext)) {
 *         // 解密
 *         String decrypted = encryptionStrategy.decrypt(ciphertext);
 *     }
 * }
 * </pre>
 * 
 * @author Cherry
 * @since 1.0.0
 * @see DefaultEncryptionStrategy
 * @see KeyProvider
 */
public interface EncryptionStrategy {

    /**
     * 加密明文数据
     * <p>
     * 将明文数据加密为密文，加密后的数据应包含加密标识前缀。
     * 实现类应确保加密过程的安全性，包括：
     * <ul>
     *   <li>使用安全的加密算法和模式</li>
     *   <li>生成随机的初始化向量(IV)</li>
     *   <li>正确处理加密异常</li>
     *   <li>避免敏感信息泄露</li>
     * </ul>
     * </p>
     * 
     * @param plaintext 明文数据，不能为null
     * @return 加密后的密文，格式为 "前缀:Base64(IV+密文)"
     * @throws IllegalArgumentException 如果明文为null或空字符串
     * @throws RuntimeException 加密失败时抛出
     */
    String encrypt(String plaintext);

    /**
     * 解密密文数据
     * <p>
     * 将密文数据解密为明文。如果输入数据不是加密数据（没有加密标识前缀），
     * 应直接返回原数据。
     * 实现类应确保解密过程的安全性，包括：
     * <ul>
     *   <li>验证加密标识前缀</li>
     *   <li>正确提取初始化向量(IV)</li>
     *   <li>使用正确的密钥进行解密</li>
     *   <li>正确处理解密异常</li>
     * </ul>
     * </p>
     * 
     * @param ciphertext 密文数据，可以为null或非加密数据
     * @return 解密后的明文，如果输入不是加密数据则返回原数据
     * @throws RuntimeException 解密失败时抛出
     */
    String decrypt(String ciphertext);

    /**
     * 判断字符串是否已加密
     * <p>
     * 通过检查字符串是否以加密标识前缀开头来判断。
     * 该方法用于在处理数据前判断数据是否需要解密。
     * </p>
     * 
     * @param text 要判断的字符串，可以为null
     * @return 如果字符串已加密返回true，否则返回false
     */
    boolean isEncrypted(String text);

    /**
     * 获取加密标识前缀
     * <p>
     * 加密标识前缀用于标识加密数据，便于识别和处理。
     * 所有加密后的数据都应以该前缀开头。
     * </p>
     * 
     * @return 加密标识前缀，例如 "ds:enc:"
     */
    String getEncryptPrefix();

    /**
     * 获取密钥
     * <p>
     * 根据密钥ID和加密算法获取对应的密钥对象。
     * 实现类应支持密钥缓存机制，避免重复获取密钥。
     * </p>
     * 
     * @param keyId 密钥ID，用于标识特定的密钥，可以为null或空字符串
     * @param algorithm 加密算法，如 "AES"、"SM4"、"DES"、"RSA"等
     * @return 密钥对象
     * @throws IllegalArgumentException 如果算法不支持或密钥ID无效
     * @throws RuntimeException 获取密钥失败时抛出
     */
    Key getKey(String keyId, String algorithm);

    /**
     * 判断是否支持指定的加密算法
     * <p>
     * 用于验证当前策略是否支持指定的加密算法。
     * 在执行加密解密操作前，应先调用此方法验证算法支持性。
     * </p>
     * 
     * @param algorithm 算法名称，如 "AES"、"SM4"、"DES"、"RSA"等
     * @return 如果支持该算法返回true，否则返回false
     */
    boolean supports(String algorithm);
}
