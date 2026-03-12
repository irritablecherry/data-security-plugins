package cn.org.cherry.data.security.info;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 更新信息封装类
 */
@Setter
@Getter
public  class UpdateInfo {
    // 通过set方法设置的字段和值
    private Map<String, Object> fieldValues = new LinkedHashMap<>();

    // 通过setSql方法设置的SQL片段
    private List<String> sqlFragments = new ArrayList<>();

    // 实体对象
    private Object entity;

    // WHERE条件
    private Map<String, Object> conditions = new LinkedHashMap<>();

    // SQL片段
    private String sqlSegment = "";

    @Override
    public String toString() {
        return "UpdateInfo{" +
                "fieldValues=" + fieldValues +
                ", sqlFragments=" + sqlFragments +
                ", entity=" + entity +
                ", conditions=" + conditions +
                ", sqlSegment='" + sqlSegment + '\'' +
                '}';
    }
}
