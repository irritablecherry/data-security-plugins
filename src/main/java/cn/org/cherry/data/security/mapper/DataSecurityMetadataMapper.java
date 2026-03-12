package cn.org.cherry.data.security.mapper;

import cn.org.cherry.data.security.entity.DataSecurityMetadata;
import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Map;

/**
 * 元数据Mapper
 */
@Mapper
public interface DataSecurityMetadataMapper extends BaseMapper<DataSecurityMetadata> {
    /**
     * 通用分页查询
     *
     * @param tableName 表名
     * @param wrapper   查询条件
     * @param page      分页参数
     * @return 分页结果
     */
    IPage<Map<String, Object>> selectPageList(@Param("tableName") String tableName,
                                              @Param("ew") QueryWrapper<?> wrapper,
                                              IPage<Map<String, Object>> page);

    /**
     * 动态表名更新方法
     * @param tableName 表名
     * @param wrapper 更新条件和设置值包装器
     * @return 影响的行数
     */
    int updateByWrapper(@Param("tableName") String tableName, @Param("ew") UpdateWrapper<?> wrapper);

    /**
     * 根据SQL查询列表
     * @param sql SQL查询语句
     * @return 结果列表
     */
    List<Map<String, Object>> selectListBySql(@Param("sql") String sql);

    /**
     * 根据QueryWrapper查询列表
     * @param tableName 表名
     * @param wrapper 查询条件包装器
     * @return 结果列表
     */
    List<Map<String, Object>> selectListByWrapper(@Param("tableName") String tableName, @Param("ew") Wrapper<?> wrapper);
}
