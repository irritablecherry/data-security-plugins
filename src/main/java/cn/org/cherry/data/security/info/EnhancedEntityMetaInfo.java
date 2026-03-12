package cn.org.cherry.data.security.info;

import cn.org.cherry.data.security.config.ConfigurationResolver;
import cn.org.cherry.data.security.interceptor.DataSecurityInterceptor.EntityMetaInfo;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Setter
@Getter
public class EnhancedEntityMetaInfo extends EntityMetaInfo {
    // getters and setters
    private ConfigurationResolver.MergedIdentificationCode mergedIdentificationConfig;
    private Map<String, ConfigurationResolver.MergedEncryptField> mergedEncryptFieldMap;

    @Override
    public boolean hasIdentificationCode() {
        return super.hasIdentificationCode() &&
                mergedIdentificationConfig != null &&
                mergedIdentificationConfig.isEnabled();
    }
}
