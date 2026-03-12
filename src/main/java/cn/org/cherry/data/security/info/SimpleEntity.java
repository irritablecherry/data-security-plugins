package cn.org.cherry.data.security.info;

import cn.org.cherry.data.security.annotation.EncryptField;
import lombok.Data;

@Data
public class SimpleEntity {
    private String simpleName;

    @EncryptField
    private String name;
    @EncryptField
    private Integer age;

    private String email;

    public SimpleEntity() {
    }

    public SimpleEntity(String simpleName, String name, Integer age, String email) {
        this.simpleName = simpleName;
        this.name = name;
        this.age = age;
        this.email = email;
    }
}
