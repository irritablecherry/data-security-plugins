package cn.org.cherry.data.security.service;

import cn.org.cherry.data.security.exception.DataSecurityException;
import cn.org.cherry.data.security.mapper.DataSecurityMetadataMapper;
import cn.org.cherry.data.security.utils.TableValidator;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * 数据安全通用服务类
 * <p>
 * 提供通用的数据安全和数据库操作服务。
 * </p>
 *
 * @author Cherry
 * @since 1.0.0
 */
@Service
public class DataSecurityCommonService {

    @Autowired
    private DataSecurityMetadataMapper dataSecurityMetadataMapper;

    /**
     * 分页查询数据
     *
     * @param tableName 表名
     * @param page 分页参数
     * @param wrapper 查询条件
     * @return 分页结果
     * @throws DataSecurityException 表名不合法时抛出
     */
    public IPage<Map<String, Object>> selectPage(String tableName,
                                                 IPage<Map<String, Object>> page,
                                                 QueryWrapper<Map<String, Object>> wrapper) {
        // 严格验证表名，防止 SQL 注入
        TableValidator.validateTableNameStrict(tableName);
        return dataSecurityMetadataMapper.selectPageList(tableName, wrapper, page);
    }

    /**
     * 根据条件更新数据
     *
     * @param tableName 表名
     * @param wrapper 更新条件
     * @throws DataSecurityException 表名不合法时抛出
     */
    public void updateByWrapper(String tableName, UpdateWrapper<Map<String, Object>> wrapper) {
        // 严格验证表名，防止 SQL 注入
        TableValidator.validateTableNameStrict(tableName);
        dataSecurityMetadataMapper.updateByWrapper(tableName, wrapper);
    }
}
