package cn.org.cherry.data.security.strategy;

import cn.org.cherry.data.security.annotation.IdentificationCode;
import lombok.Getter;

import java.util.Map;

/**
 * 鉴别码生成策略接口
 * 允许用户自定义鉴别码的生成和验证逻辑
 */
public interface IdentificationCodeStrategy {

    /**
     * 生成鉴别码
     * @param dataMap 参与生成鉴别码的数据
     * @param annotation 鉴别码注解配置
     * @return 鉴别码信息（包含鉴别码内容和鉴别码）
     */
    IdentificationCodeInfo generate(Map<String, Object> dataMap,
                                    IdentificationCode annotation);

    /**
     * 验证鉴别码
     * @param storedCode 存储的鉴别码
     * @param dataMap 当前数据
     * @param annotation 鉴别码注解配置
     * @return 验证结果
     */
    boolean verify(String storedCode,
                   Map<String, Object> dataMap,
                   IdentificationCode annotation);

    /**
     * 鉴别码信息
     */
    @Getter
    class IdentificationCodeInfo {
        // getters
        private final String content;  // 鉴别码内容
        private final String code;     // 鉴别码值

        public IdentificationCodeInfo(String content, String code) {
            this.content = content;
            this.code = code;
        }

    }
}
