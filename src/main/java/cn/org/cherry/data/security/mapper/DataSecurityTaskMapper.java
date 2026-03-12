package cn.org.cherry.data.security.mapper;

import cn.org.cherry.data.security.entity.DataSecurityTask;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
 * 数据执行任务Mapper
 */
@Mapper
public interface DataSecurityTaskMapper extends BaseMapper<DataSecurityTask> {
}
