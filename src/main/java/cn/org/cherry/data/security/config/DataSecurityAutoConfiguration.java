package cn.org.cherry.data.security.config;

import cn.org.cherry.data.security.strategy.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * 数据安全插件配置
 */
@Configuration
public class DataSecurityAutoConfiguration {

    /**
     * 默认鉴别码策略
     */
    @Bean
    @ConditionalOnMissingBean(IdentificationCodeStrategy.class)
    public IdentificationCodeStrategy defaultIdentificationCodeStrategy() {
        return new DefaultIdentificationCodeStrategy();
    }

    /**
     * 默认加密策略
     */
    @Bean
    @ConditionalOnMissingBean(EncryptionStrategy.class)
    public EncryptionStrategy defaultEncryptionStrategy() {
        return new DefaultEncryptionStrategy();
    }

    /**
     * 默认密钥提供器
     */
    @Bean
    @ConditionalOnMissingBean(KeyProvider.class)
    public KeyProvider defaultKeyProvider() {
        return new DefaultKeyProvider();
    }


    /**
     * 数据库方言工厂
     */
    @Bean
    @ConditionalOnMissingBean
    public DatabaseDialectFactory databaseDialectFactory() {
        return new DatabaseDialectFactory();
    }

    /**
     * 异步任务线程池
     */
    @Bean("identificationTaskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(100);
        executor.setKeepAliveSeconds(60);
        executor.setThreadNamePrefix("identification-task-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }
}
