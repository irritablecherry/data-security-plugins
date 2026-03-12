package cn.org.cherry.data.security.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
@ConfigurationProperties(prefix = "tenant")
public class DataSecurityRuoYiProperties {
    private Boolean enable = false;
    private Set<String> ignoreTables = new HashSet<>();
}
