package io.github.dbstarll.certs.utils;

import io.github.dbstarll.utils.lang.security.InstanceException;
import io.github.dbstarll.utils.lang.security.SecureRandomAlgorithm;
import io.github.dbstarll.utils.lang.security.SecurityFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SecureRandomUtils {
    private SecureRandomUtils() {
        // 禁止实例化
    }

    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(() -> {
        try {
            return SecurityFactory.builder(SecureRandomAlgorithm.SHA1PRNG).build();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InstanceException e) {
            throw new RuntimeException(e);
        }
    });

    /**
     * 获得线程共享的SecureRandom.
     *
     * @return SecureRandom
     */
    public static SecureRandom get() {
        return SECURE_RANDOM.get();
    }
}
