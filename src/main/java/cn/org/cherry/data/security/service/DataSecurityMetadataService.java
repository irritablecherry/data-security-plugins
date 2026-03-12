package cn.org.cherry.data.security.service;

import cn.org.cherry.data.security.entity.DataSecurityMetadata;
import cn.org.cherry.data.security.mapper.DataSecurityMetadataMapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * 鉴别码元数据服务
 */
@Service
public class DataSecurityMetadataService extends ServiceImpl<DataSecurityMetadataMapper, DataSecurityMetadata> {

    /**
     * 根据表名获取元数据
     */
    public DataSecurityMetadata getByTableName(String tableName) {
        QueryWrapper<DataSecurityMetadata> wrapper = new QueryWrapper<>();
        wrapper.eq("table_name", tableName);
        return getOne(wrapper);
    }

    /**
     * 检查表是否需要重新生成鉴别码
     */
    public boolean needRegenerate(String tableName) {
        DataSecurityMetadata metadata = getByTableName(tableName);
        if (metadata == null) {
            return false;
        }
        return metadata.getNeedRegenerate() != null && metadata.getNeedRegenerate();
    }
}
