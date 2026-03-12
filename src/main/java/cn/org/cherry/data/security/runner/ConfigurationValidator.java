package cn.org.cherry.data.security.runner;

import cn.org.cherry.data.security.config.DataSecurityProperties;
import com.baomidou.mybatisplus.autoconfigure.MybatisPlusProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * 配置优先级验证器
 * 启动时验证配置是否正确加载
 */

@Slf4j
@Order(1)
@Component
public class ConfigurationValidator implements ApplicationRunner {

    @Autowired
    private DataSecurityProperties properties;

    @Autowired
    private MybatisPlusProperties mybatisPlusProperties;

    @Override
    public void run(ApplicationArguments args) {
        log.info("==========  MybatisPlus配置  ==========");
        log.info("=== 全局插入策略: {}", mybatisPlusProperties.getGlobalConfig().getDbConfig().getInsertStrategy());
        log.info("=== 全局更新策略: {}", mybatisPlusProperties.getGlobalConfig().getDbConfig().getUpdateStrategy());
        log.info("========== 数据安全插件配置验证 ==========");
        log.info("=== 插件是否启用: {}", properties.isEnabled());
        log.info("=== 自动建表是否启用: {}", properties.getAutoCreate().isEnabled());
        log.info("======================================");
        log.info("=== 鉴别码功能是否启用: {}", properties.getIdentification().isEnabled());
        log.info("=== 默认鉴别码内容字段: {}", properties.getIdentification().getContentField());
        log.info("=== 默认鉴别码字段: {}", properties.getIdentification().getCodeField());
        log.info("=== 默认鉴别码验证字段: {}", properties.getIdentification().getCheckResultField());
        log.info("=== 默认哈希算法: {}", properties.getIdentification().getAlgorithm());
        log.info("======================================");
        log.info("=== 加密是否启用: {}", properties.getEncryption().isEnabled());
        log.info("=== 加密算法: {}", properties.getEncryption().getAlgorithm());
        log.info("=== 加密策略: {}", properties.getEncryption().getStrategy());
        log.info("=== 加密秘钥提供器: {}", properties.getEncryption().getKeyProvider());
        log.info("======================================");
    }
}
