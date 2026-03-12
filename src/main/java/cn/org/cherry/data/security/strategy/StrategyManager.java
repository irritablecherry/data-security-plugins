package cn.org.cherry.data.security.strategy;

import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 策略管理器
 * <p>
 * 负责管理所有策略实例，包括默认策略和自定义策略。
 * 提供策略的注册、获取和切换功能。
 * </p>
 * 
 * <h3>核心功能：</h3>
 * <ul>
 *   <li>默认策略管理：提供默认的加密、鉴别码和密钥提供策略</li>
 *   <li>自定义策略加载：自动从Spring容器加载自定义策略</li>
 *   <li>策略缓存：缓存策略实例，提高访问性能</li>
 *   <li>策略切换：支持运行时切换策略</li>
 * </ul>
 * 
 * <h3>使用示例：</h3>
 * <pre>
 * &#064;Autowired
 * private StrategyManager strategyManager;
 * 
 * // 获取默认加密策略
 * EncryptionStrategy defaultStrategy = strategyManager.getEncryptionStrategy(null);
 * 
 * // 获取指定名称的加密策略
 * EncryptionStrategy customStrategy = strategyManager.getEncryptionStrategy("customEncryptionStrategy");
 * 
 * // 获取密钥提供器
 * KeyProvider keyProvider = strategyManager.getKeyProvider("kmsKeyProvider");
 * </pre>
 * 
 * <h3>自定义策略注册：</h3>
 * <pre>
 * // 实现自定义加密策略
 * &#064;Component("customEncryptionStrategy")
 * public class CustomEncryptionStrategy implements EncryptionStrategy {
 *     // 实现方法...
 * }
 * 
 * // 策略会自动被StrategyManager加载和管理
 * </pre>
 * 
 * @author Cherry
 * @since 1.0.0
 * @see EncryptionStrategy
 * @see IdentificationCodeStrategy
 * @see KeyProvider
 */
@Slf4j
@Component
public class StrategyManager {

    /**
     * Spring应用上下文
     */
    private final ApplicationContext applicationContext;

    /**
     * 默认鉴别码策略
     */
    private DefaultIdentificationCodeStrategy defaultIdentificationCodeStrategy;

    /**
     * 默认加密策略
     */
    private DefaultEncryptionStrategy defaultEncryptionStrategy;

    /**
     * 默认密钥提供器
     */
    private DefaultKeyProvider defaultKeyProvider;

    /**
     * 自定义鉴别码策略缓存
     */
    private final Map<String, IdentificationCodeStrategy> identificationCodeStrategies = new ConcurrentHashMap<>();

    /**
     * 自定义加密策略缓存
     */
    private final Map<String, EncryptionStrategy> encryptionStrategies = new ConcurrentHashMap<>();

    /**
     * 自定义密钥提供器缓存
     */
    private final Map<String, KeyProvider> keyProviders = new ConcurrentHashMap<>();

    /**
     * 构造函数
     * <p>
     * 初始化策略管理器，加载默认策略和自定义策略。
     * </p>
     * 
     * @param applicationContext Spring应用上下文
     */
    public StrategyManager(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        initDefaultStrategies();
        loadCustomStrategies();
    }

    /**
     * 初始化默认策略
     * <p>
     * 从Spring容器中获取默认策略实例，确保依赖注入正确。
     * </p>
     */
    private void initDefaultStrategies() {
        log.debug("初始化默认策略...");
        
        this.defaultIdentificationCodeStrategy = applicationContext.getBean(DefaultIdentificationCodeStrategy.class);
        this.defaultEncryptionStrategy = applicationContext.getBean(DefaultEncryptionStrategy.class);
        this.defaultKeyProvider = applicationContext.getBean(DefaultKeyProvider.class);
        
        log.info("默认策略初始化完成: identificationCodeStrategy={}, encryptionStrategy={}, keyProvider={}",
                defaultIdentificationCodeStrategy.getClass().getSimpleName(),
                defaultEncryptionStrategy.getClass().getSimpleName(),
                defaultKeyProvider.getClass().getSimpleName());
    }

    /**
     * 加载自定义策略
     * <p>
     * 从Spring容器中加载所有自定义策略实例，并注册到策略缓存中。
     * 自定义策略是指非默认实现类的策略实例。
     * </p>
     */
    private void loadCustomStrategies() {
        log.debug("加载自定义策略...");
        
        loadCustomIdentificationCodeStrategies();
        loadCustomEncryptionStrategies();
        loadCustomKeyProviders();
        
        log.info("自定义策略加载完成: identificationCodeStrategies={}, encryptionStrategies={}, keyProviders={}",
                identificationCodeStrategies.size(),
                encryptionStrategies.size(),
                keyProviders.size());
    }

    /**
     * 加载自定义鉴别码策略
     */
    private void loadCustomIdentificationCodeStrategies() {
        Map<String, IdentificationCodeStrategy> strategies = applicationContext.getBeansOfType(IdentificationCodeStrategy.class);
        strategies.forEach((name, strategy) -> {
            if (!(strategy instanceof DefaultIdentificationCodeStrategy)) {
                identificationCodeStrategies.put(name, strategy);
                log.debug("加载自定义鉴别码策略: {}", name);
            }
        });
    }

    /**
     * 加载自定义加密策略
     */
    private void loadCustomEncryptionStrategies() {
        Map<String, EncryptionStrategy> strategies = applicationContext.getBeansOfType(EncryptionStrategy.class);
        strategies.forEach((name, strategy) -> {
            if (!(strategy instanceof DefaultEncryptionStrategy)) {
                encryptionStrategies.put(name, strategy);
                log.debug("加载自定义加密策略: {}", name);
            }
        });
    }

    /**
     * 加载自定义密钥提供器
     */
    private void loadCustomKeyProviders() {
        Map<String, KeyProvider> providers = applicationContext.getBeansOfType(KeyProvider.class);
        providers.forEach((name, provider) -> {
            if (!(provider instanceof DefaultKeyProvider)) {
                keyProviders.put(name, provider);
                log.debug("加载自定义密钥提供器: {}", name);
            }
        });
    }

    /**
     * 获取鉴别码策略
     * <p>
     * 根据策略名称获取对应的鉴别码策略实例。
     * 如果策略名称为空或不存在，则返回默认策略。
     * </p>
     * 
     * @param strategyName 策略名称，可以为null或空字符串
     * @return 鉴别码策略实例
     */
    public IdentificationCodeStrategy getIdentificationCodeStrategy(String strategyName) {
        if (StringUtils.isNotBlank(strategyName)) {
            IdentificationCodeStrategy strategy = identificationCodeStrategies.get(strategyName);
            if (strategy != null) {
                log.debug("使用自定义鉴别码策略: {}", strategyName);
                return strategy;
            }
            log.warn("未找到指定的鉴别码策略: {}, 使用默认策略", strategyName);
        }
        return defaultIdentificationCodeStrategy;
    }

    /**
     * 获取加密策略
     * <p>
     * 根据策略名称获取对应的加密策略实例。
     * 如果策略名称为空或不存在，则返回默认策略。
     * </p>
     * 
     * @param strategyName 策略名称，可以为null或空字符串
     * @return 加密策略实例
     */
    public EncryptionStrategy getEncryptionStrategy(String strategyName) {
        if (StringUtils.isNotBlank(strategyName)) {
            EncryptionStrategy strategy = encryptionStrategies.get(strategyName);
            if (strategy != null) {
                log.debug("使用自定义加密策略: {}", strategyName);
                return strategy;
            }
            log.warn("未找到指定的加密策略: {}, 使用默认策略", strategyName);
        }
        return defaultEncryptionStrategy;
    }

    /**
     * 获取密钥提供器
     * <p>
     * 根据提供器名称获取对应的密钥提供器实例。
     * 如果提供器名称为空或不存在，则返回默认提供器。
     * </p>
     * 
     * @param providerName 提供器名称，可以为null或空字符串
     * @return 密钥提供器实例
     */
    public KeyProvider getKeyProvider(String providerName) {
        if (StringUtils.isNotBlank(providerName)) {
            KeyProvider provider = keyProviders.get(providerName);
            if (provider != null) {
                log.debug("使用自定义密钥提供器: {}", providerName);
                return provider;
            }
            log.warn("未找到指定的密钥提供器: {}, 使用默认提供器", providerName);
        }
        return defaultKeyProvider;
    }

    /**
     * 注册自定义鉴别码策略
     * 
     * @param name 策略名称
     * @param strategy 策略实例
     */
    public void registerIdentificationCodeStrategy(String name, IdentificationCodeStrategy strategy) {
        if (StringUtils.isBlank(name) || strategy == null) {
            throw new IllegalArgumentException("策略名称和实例不能为空");
        }
        identificationCodeStrategies.put(name, strategy);
        log.info("注册自定义鉴别码策略: {}", name);
    }

    /**
     * 注册自定义加密策略
     * 
     * @param name 策略名称
     * @param strategy 策略实例
     */
    public void registerEncryptionStrategy(String name, EncryptionStrategy strategy) {
        if (StringUtils.isBlank(name) || strategy == null) {
            throw new IllegalArgumentException("策略名称和实例不能为空");
        }
        encryptionStrategies.put(name, strategy);
        log.info("注册自定义加密策略: {}", name);
    }

    /**
     * 注册自定义密钥提供器
     * 
     * @param name 提供器名称
     * @param provider 提供器实例
     */
    public void registerKeyProvider(String name, KeyProvider provider) {
        if (StringUtils.isBlank(name) || provider == null) {
            throw new IllegalArgumentException("提供器名称和实例不能为空");
        }
        keyProviders.put(name, provider);
        log.info("注册自定义密钥提供器: {}", name);
    }

    /**
     * 获取所有自定义鉴别码策略名称
     * 
     * @return 策略名称集合
     */
    public java.util.Set<String> getIdentificationCodeStrategyNames() {
        return identificationCodeStrategies.keySet();
    }

    /**
     * 获取所有自定义加密策略名称
     * 
     * @return 策略名称集合
     */
    public java.util.Set<String> getEncryptionStrategyNames() {
        return encryptionStrategies.keySet();
    }

    /**
     * 获取所有自定义密钥提供器名称
     * 
     * @return 提供器名称集合
     */
    public java.util.Set<String> getKeyProviderNames() {
        return keyProviders.keySet();
    }
}
