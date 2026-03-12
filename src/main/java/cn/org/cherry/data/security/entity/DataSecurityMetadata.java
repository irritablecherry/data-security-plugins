package cn.org.cherry.data.security.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Date;

/**
 * 鉴别码配置元数据
 */
@Data
@TableName("data_security_metadata")
public class DataSecurityMetadata {

    @TableId(type = IdType.AUTO)
    private Long id;

    @TableField("table_name")
    private String tableName;

    @TableField("entity_class")
    private String entityClass;

    @TableField("content_field")
    private String contentField;

    @TableField("code_field")
    private String codeField;

    @TableField("include_fields_hash")
    private String includeFieldsHash;

    @TableField("include_fields_json")
    private String includeFieldsJson;

    @TableField("algorithm")
    private String algorithm;

    @TableField("field_created")
    private Boolean fieldCreated;

    @TableField("data_regenerated")
    private Boolean dataRegenerated;

    @TableField("last_regenerate_time")
    private Date lastRegenerateTime;

    @TableField("record_count")
    private Integer recordCount;

    @TableField("regenerated_count")
    private Integer regeneratedCount;

    @TableField("version")
    private Integer version;

    @TableField(value = "created_time", fill = FieldFill.INSERT)
    private LocalDateTime createdTime;

    @TableField(value = "updated_time", fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedTime;

    // 辅助字段
    @TableField(exist = false)
    private Boolean includeFieldsChanged = false;

    @TableField(exist = false)
    private Boolean needRegenerate = false;


}
