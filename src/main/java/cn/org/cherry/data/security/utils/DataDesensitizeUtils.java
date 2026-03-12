package cn.org.cherry.data.security.utils;

import cn.org.cherry.data.security.annotation.EncryptField;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;

/**
 * 数据脱敏工具类
 */
public class DataDesensitizeUtils {

    /**
     * 脱敏处理
     */
    public static String desensitize(String data, String rule) {
        if (StringUtils.isBlank(data) || data.length() <= 1) {
            return data;
        }

        if (StringUtils.isBlank(rule)) {
            return data;
        }

        try {
            String[] parts = rule.split("@");
            if (parts.length != 2) {
                return maskAll(data);
            }

            int prefix = Integer.parseInt(parts[0]);
            int suffix = Integer.parseInt(parts[1]);

            if (prefix < 0 || suffix < 0) {
                return maskAll(data);
            }

            if (data.length() <= prefix + suffix) {
                return maskAll(data);
            }

            StringBuilder result = new StringBuilder();
            result.append(data.substring(0, prefix));

            for (int i = 0; i < data.length() - prefix - suffix; i++) {
                result.append("*");
            }

            result.append(data.substring(data.length() - suffix));
            return result.toString();
        } catch (Exception e) {
            return maskAll(data);
        }
    }

    /**
     * 全部脱敏
     */
    private static String maskAll(String data) {
        if (StringUtils.isBlank(data)) {
            return data;
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < data.length(); i++) {
            result.append("*");
        }
        return result.toString();
    }

    /**
     * 根据加密注解脱敏
     */
    public static String desensitizeByAnnotation(String data, EncryptField annotation) {
        if (annotation == null || !annotation.desensitizeInLog()) {
            return data;
        }

        return desensitize(data, annotation.desensitizeRule());
    }
}
