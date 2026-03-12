# Data Security Plugins

[![License](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-8+-orange.svg)](https://openjdk.java.net/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-2.7.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Maven](https://img.shields.io/badge/Maven-3.6+-red.svg)](https://maven.apache.org/)

## 📖 项目简介

**Data Security Plugins** 是一款基于 Spring Boot 和 MyBatis 的数据安全中间件，旨在为企业级应用提供透明、无侵入的数据安全保护方案。

该插件通过 MyBatis 拦截器机制，在 SQL 执行层自动完成数据的加密、解密、鉴别码生成与校验、数据脱敏等操作，无需修改任何业务代码即可实现数据库层面的数据安全保护。支持字段级加密注解（@EncryptField）和类级鉴别码注解（@IdentificationCode），提供 MD5、SHA-256、SHA-512、SM3 等多种哈希算法。

核心特性包括：零代码侵入、多数据库兼容（MySQL、Oracle、PostgreSQL、达梦、人大金仓等）、灵活的策略扩展机制、自定义密钥管理、日志脱敏等。适用于对敏感数据（如身份证号、手机号、银行卡号等）有加密存储需求，以及对数据完整性有校验要求的各类业务场景。

## ✨ 核心特性

- 🔐 **透明加密解密** - 基于注解的字段级加密，自动完成加解密过程
- 🏷️ **鉴别码生成** - 支持多种哈希算法（MD5、SHA-256、SHA-512、SM3）
- 📝 **数据脱敏** - 自定义脱敏规则，保护敏感信息展示
- 🗄️ **多数据库支持** - 支持 MySQL、Oracle、PostgreSQL、SQL Server 等主流数据库
- 🚀 **零侵入** - 基于 MyBatis 拦截器，无需修改现有业务代码
- 🔧 **灵活配置** - 支持自定义加密策略、密钥提供者

## 📦 技术栈

| 技术 | 版本 |
|------|------|
| Java | 8+ |
| Spring Boot | 2.7.x |
| Spring Framework | 5.3.x |
| MyBatis | 3.5.x |
| MyBatis-Plus | 3.5.x |
| FastJSON | 1.2.x |
| Lombok | 1.18.x |

## 🚀 快速开始

### 1. 添加依赖

```xml
<dependency>
    <groupId>cn.org.cherry</groupId>
    <artifactId>data-security-plugins</artifactId>
    <version>1.0</version>
</dependency>
```

### 2. 配置启用

在 `application.yml` 中配置：

```yaml
data:
  security:
    enabled: true
```

### 3. 使用加密字段

```java
import cn.org.cherry.data.security.annotation.EncryptField;

public class User {
    
    @EncryptField(desensitizeInLog = true, desensitizeRule = "3@4")
    private String phone;
    
    @EncryptField
    private String idCard;
    
    // getters and setters...
}
```

### 4. 使用鉴别码

```java
import cn.org.cherry.data.security.annotation.IdentificationCode;

@IdentificationCode(
    includeFields = {"name", "phone", "email"}
)
public class Order {
    
    private String name;
    private String phone;
    private String email;
    private String identificationCode;
    private Boolean identificationValid;
    
    // getters and setters...
}
```

## 📖 注解说明

### @EncryptField（字段加密）

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| desensitizeInLog | boolean | true | 是否在日志中脱敏显示 |
| desensitizeRule | String | "3@4" | 脱敏规则，格式：前缀保留位数@后缀保留位数 |

### @IdentificationCode（鉴别码）

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| contentField | String | "" | 鉴别码内容字段名 |
| codeField | String | "identification_code" | 鉴别码字段名 |
| includeFields | String[] | {} | 参与生成鉴别码的字段 |
| excludeFields | String[] | {} | 排除的字段 |
| algorithm | String | "SHA-256" | 哈希算法：MD5/SHA-256/SHA-512/SM3 |
| returnCheckResult | boolean | true | 是否返回校验结果 |
| checkResultField | String | "identificationValid" | 校验结果字段名 |
| strategy | String | "" | 鉴别码策略 Bean 名称 |
| dataCollector | String | "" | 数据收集器 Bean 名称 |

## 🗄️ 支持的数据库

- **关系型数据库**：MySQL、Oracle、PostgreSQL、SQL Server、H2、SQLite
- **国产数据库**：达梦 (DM)、人大金仓 (KingbaseES)、神舟 (Oscar)

## 🔧 自定义扩展

### 自定义加密策略

```java
@Component
public class CustomEncryptionStrategy implements EncryptionStrategy {
    @Override
    public String encrypt(String data, String key) {
        // 自定义加密逻辑
    }
    
    @Override
    public String decrypt(String data, String key) {
        // 自定义解密逻辑
    }
}
```

### 自定义密钥提供者

```java
@Component
public class CustomKeyProvider implements KeyProvider {
    @Override
    public String getKey(String tableName, String columnName) {
        // 自定义密钥获取逻辑
    }
}
```

## 📁 项目结构

```
data-security-plugins
├── src/main/java/cn/org/cherry/data/security/
│   ├── annotation/          # 注解定义
│   │   ├── EncryptField.java
│   │   └── IdentificationCode.java
│   ├── config/              # 配置类
│   │   ├── DataSecurityAutoConfiguration.java
│   │   ├── DataSecurityProperties.java
│   │   └── DatabaseDialectFactory.java
│   ├── interceptor/         # MyBatis 拦截器
│   ├── strategy/            # 加密/鉴别码策略
│   ├── service/             # 服务层
│   ├── mapper/              # 数据访问层
│   ├── utils/               # 工具类
│   ├── exception/           # 异常定义
│   └── info/                # 信息实体
└── src/test/                # 测试代码
```

## ⚙️ 配置项

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| data.security.enabled | 是否启用插件 | true |
| data.security.encrypt.enabled | 是否启用加密 | true |
| data.security.identification.enabled | 是否启用鉴别码 | true |

## 📄 License

GNU General Public License v2.0 (GPL-2.0)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📫️ 联系方式

- 作者：Cherry
- 邮箱：irritablecherry@qq.com
- 项目地址：https://github.com/irritablecherry/data-security-plugins

## 📱 关注我
- 如需获得商业授权请关注公众号联系作者

| 公众号 | 
|:------:|
| ![公众号](qrcode.png) |

---

**如果本项目对您有帮助，请给个 ⭐ Star 支持一下！**
