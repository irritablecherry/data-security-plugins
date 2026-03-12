package cn.org.cherry.data.security.exception;

/**
 * 鉴别码异常
 * <p>
 * 用于鉴别码生成和验证中的异常处理。
 * </p>
 *
 * @author Cherry
 * @since 1.0.0
 */
public class IdentificationCodeException extends DataSecurityException {

    /**
     * 构造异常
     *
     * @param message 异常消息
     */
    public IdentificationCodeException(String message) {
        super("IDENTIFICATION_CODE_ERROR", message);
    }

    /**
     * 构造异常
     *
     * @param message 异常消息
     * @param cause 异常原因
     */
    public IdentificationCodeException(String message, Throwable cause) {
        super("IDENTIFICATION_CODE_ERROR", message, cause);
    }
}
