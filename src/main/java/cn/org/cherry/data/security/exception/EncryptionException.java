package cn.org.cherry.data.security.exception;

/**
 * 加密异常
 * <p>
 * 用于加密/解密操作中的异常处理。
 * </p>
 *
 * @author Cherry
 * @since 1.0.0
 */
public class EncryptionException extends DataSecurityException {

    /**
     * 构造异常
     *
     * @param message 异常消息
     */
    public EncryptionException(String message) {
        super("ENCRYPTION_ERROR", message);
    }

    /**
     * 构造异常
     *
     * @param message 异常消息
     * @param cause 异常原因
     */
    public EncryptionException(String message, Throwable cause) {
        super("ENCRYPTION_ERROR", message, cause);
    }
}
