package cn.org.cherry.data.security.annotation;

import java.lang.annotation.*;

/**
 * 扩展的鉴别码注解
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface IdentificationCode {

    /**
     * 鉴别码内容字段名（存储原始数据的JSON字符串）
     * 默认值：默认为空 即不存储 identification_content
     */
    String contentField() default "";

    /**
     * 鉴别码字段名（存储鉴别码哈希值）
     * 默认值：identification_code
     */
    String codeField() default "identification_code";

    /**
     * 参与生成鉴别码的字段
     * 如果为空，则使用所有非鉴别码字段
     */
    String[] includeFields() default {};

    /**
     * 排除的字段（不参与生成鉴别码）
     */
    String[] excludeFields() default {};

    /**
     * 哈希算法
     * 可选值：MD5, SHA-256, SHA-512, SM3
     */
    String algorithm() default "SHA-256";

    /**
     * 是否返回校验结果标识
     */
    boolean returnCheckResult() default true;

    /**
     * 校验结果字段名
     * 仅在returnCheckResult为true时生效
     */
    String checkResultField() default "identificationValid";

    /**
     * 鉴别码策略Bean名称
     * 如果为空，使用默认策略
     */
    String strategy() default "";

    /**
     * 数据收集器Bean名称
     * 用于自定义收集哪些字段参与鉴别码生成
     */
    String dataCollector() default "";
}
