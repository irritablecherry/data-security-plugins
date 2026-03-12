package cn.org.cherry.data.security.service;

import cn.org.cherry.data.security.entity.DataSecurityTask;
import cn.org.cherry.data.security.mapper.DataSecurityTaskMapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 鉴别码重新生成任务服务
 */
@Service
public class DataSecurityTaskService extends ServiceImpl<DataSecurityTaskMapper, DataSecurityTask> {

    /**
     * 获取正在运行的任务
     */
    public List<DataSecurityTask> getRunningTasks() {
        QueryWrapper<DataSecurityTask> wrapper = new QueryWrapper<>();
        wrapper.eq("task_status", DataSecurityTask.TaskStatus.RUNNING.name());
        return list(wrapper);
    }
}