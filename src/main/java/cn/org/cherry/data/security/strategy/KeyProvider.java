package cn.org.cherry.data.security.strategy;

import cn.org.cherry.data.security.annotation.EncryptField;

import java.lang.reflect.Field;
import java.security.Key;

/**
 * 密钥提供器接口
 * 支持从不同来源获取密钥，如配置文件、KMS等
 */
public interface KeyProvider {

    /**
     * 获取密钥
     * @param keyId 密钥ID
     * @param algorithm 加密算法
     * @return 密钥对象
     */
    Key getKey(String keyId, String algorithm);

    /**
     * 判断是否支持指定的算法
     * @param algorithm 加密算法
     * @return 是否支持
     */
    default boolean supports(String algorithm) {
        return true;
    }
}