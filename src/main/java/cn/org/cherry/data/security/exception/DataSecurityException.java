package cn.org.cherry.data.security.exception;

/**
 * 数据安全异常基类
 * <p>
 * 用于数据安全插件的异常处理。
 * </p>
 *
 * @author Cherry
 * @since 1.0.0
 */
public class DataSecurityException extends RuntimeException {

    /**
     * 错误码
     */
    private final String code;

    /**
     * 构造异常
     *
     * @param message 异常消息
     */
    public DataSecurityException(String message) {
        super(message);
        this.code = "DATA_SECURITY_ERROR";
    }

    /**
     * 构造异常
     *
     * @param message 异常消息
     * @param cause 异常原因
     */
    public DataSecurityException(String message, Throwable cause) {
        super(message, cause);
        this.code = "DATA_SECURITY_ERROR";
    }

    /**
     * 构造异常
     *
     * @param code 错误码
     * @param message 异常消息
     */
    public DataSecurityException(String code, String message) {
        super(message);
        this.code = code;
    }

    /**
     * 构造异常
     *
     * @param code 错误码
     * @param message 异常消息
     * @param cause 异常原因
     */
    public DataSecurityException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    /**
     * 获取错误码
     *
     * @return 错误码
     */
    public String getCode() {
        return code;
    }
}
