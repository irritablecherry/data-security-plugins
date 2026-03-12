package cn.org.cherry.data.security.runner;

import cn.org.cherry.data.security.service.DataSecurityMetadataManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Order(2)
@Component
@DependsOn("configurationValidator")
public class DataSecurityHandler implements ApplicationRunner {

    @Autowired
    DataSecurityMetadataManager dataSecurityMetadataManager;

    @Override
    public void run(ApplicationArguments args) {
        dataSecurityMetadataManager.init();
    }
}
