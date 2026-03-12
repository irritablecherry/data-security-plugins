package cn.org.cherry.data.security.info;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ExtractSetResult {
    //更新列的集合
    private Map<String, Object> columnDataMap;
    //列字段映射的参数
    private Map<String, String> columnMappingParam;
    //列字段映射的索引参数
    private Map<String, String> columnMappingIndexParam;
}
