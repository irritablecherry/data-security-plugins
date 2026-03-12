package cn.org.cherry.data.security.strategy;

import cn.org.cherry.data.security.annotation.IdentificationCode;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import org.springframework.stereotype.Component;
import org.springframework.util.DigestUtils;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 默认鉴别码策略
 * 使用JSON序列化和哈希算法
 */
@Component
public class DefaultIdentificationCodeStrategy implements IdentificationCodeStrategy {

    @Override
    public IdentificationCodeInfo generate(Map<String, Object> dataMap,
                                           IdentificationCode annotation) {
        // 生成JSON字符串
        // 使用Stream API排序
        Map<String, Object> sortedDataMap = dataMap.entrySet().stream()
                .filter(entry -> entry.getValue() != null) // 过滤掉值为null的字段
                .sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (e1, e2) -> e1,
                        LinkedHashMap::new));
        String jsonContent = JSON.toJSONString(sortedDataMap);
        // 根据配置的算法生成哈希
        String algorithm = annotation.algorithm();
        String identificationCode = generateHash(jsonContent, algorithm);

        return new IdentificationCodeInfo(jsonContent, identificationCode);
    }

    @Override
    public boolean verify(String storedCode,
                          Map<String, Object> dataMap,
                          IdentificationCode annotation) {
        if (StringUtils.isBlank(storedCode)) {
            return false;
        }
        //生成当前数据的鉴别码信息
        IdentificationCodeInfo codeInfo = generate(dataMap, annotation);
        if (codeInfo == null) {
            return false;
        }
        // 比较当前鉴别码和存储的鉴别码 看是否一致
        return storedCode.equals(codeInfo.getCode());
    }

    private String generateHash(String data, String algorithm) {
        if (StringUtils.isBlank(data)) {
            return "";
        }

        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);

        switch (algorithm.toUpperCase()) {
            case "MD5":
                return DigestUtils.md5DigestAsHex(dataBytes);
            case "SHA-256":
                return sha256DigestAsHex(dataBytes);
            case "SHA-512":
                return sha512DigestAsHex(dataBytes);
            case "SM3":
                return sm3Hash(dataBytes);
            default:
                return sha256DigestAsHex(dataBytes);
        }
    }

    public static String sha256DigestAsHex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(data);
            // 将字节数组转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("calculate SHA256 error", ex);
        }
    }

    /**
     * 计算字节数组的SHA-512哈希值，返回十六进制字符串
     *
     * @param dataBytes 输入数据字节数组
     * @return SHA-512哈希的十六进制字符串
     */
    public static String sha512DigestAsHex(byte[] dataBytes) {

        try {
            // 获取SHA-512 MessageDigest实例
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            // 计算哈希值
            byte[] hashBytes = digest.digest(dataBytes);

            // 将字节数组转换为十六进制字符串
            return bytesToHex(hashBytes);
        } catch (Exception ex) {
            throw new RuntimeException("calculate SHA512 error", ex);
        }
    }

    /**
     * 字节数组转十六进制字符串
     *
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private String sm3Hash(byte[] data) {
        // 国密SM3实现
        try {
            // 需要引入BouncyCastle
            // 这里简化实现
            return sha256DigestAsHex(data);
        } catch (Exception e) {
            throw new RuntimeException("SM3 hash error", e);
        }
    }
}
