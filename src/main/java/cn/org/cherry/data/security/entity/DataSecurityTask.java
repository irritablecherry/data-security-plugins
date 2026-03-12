package cn.org.cherry.data.security.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 数据执行任务
 */
@Data
@TableName("data_security_task")
public class DataSecurityTask {

    public enum TaskStatus {
        PENDING,    // 等待中
        RUNNING,    // 运行中
        COMPLETED,  // 已完成
        FAILED      // 失败
    }
    public enum TaskType {
        IDENTIFICATION_CODE,    // 等待中
        ENCRYPT
    }

    @TableId(type = IdType.AUTO)
    private Long id;

    @TableField("table_name")
    private String tableName;

    @TableField("task_type")
    private String taskType;

    @TableField("task_status")
    private String taskStatus;

    @TableField("include_fields_hash_before")
    private String includeFieldsHashBefore;

    @TableField("include_fields_hash_after")
    private String includeFieldsHashAfter;

    @TableField("total_records")
    private Integer totalRecords;

    @TableField("processed_records")
    private Integer processedRecords;

    @TableField("success_records")
    private Integer successRecords;

    @TableField("failed_records")
    private Integer failedRecords;

    @TableField("error_message")
    private String errorMessage;

    @TableField("start_time")
    private LocalDateTime startTime;

    @TableField("end_time")
    private LocalDateTime endTime;

    @TableField("created_by")
    private String createdBy;

    @TableField(value = "created_time", fill = FieldFill.INSERT)
    private LocalDateTime createdTime;

    @TableField(value = "updated_time", fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedTime;

    // 辅助方法
    public boolean isPending() {
        return TaskStatus.PENDING.name().equals(taskStatus);
    }

    public boolean isRunning() {
        return TaskStatus.RUNNING.name().equals(taskStatus);
    }

    public boolean isCompleted() {
        return TaskStatus.COMPLETED.name().equals(taskStatus);
    }

    public boolean isFailed() {
        return TaskStatus.FAILED.name().equals(taskStatus);
    }
}
