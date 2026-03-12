package cn.org.cherry.data.security.annotation;

import java.lang.annotation.*;

/**
 * 扩展的加密字段注解
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface EncryptField {
    /**
     * 是否在日志中脱敏显示
     */
    boolean desensitizeInLog() default true;

    /**
     * 脱敏规则
     * 格式：前缀保留位数@后缀保留位数
     * 例如：3@4 表示保留前3位和后4位
     */
    String desensitizeRule() default "3@4";

}
