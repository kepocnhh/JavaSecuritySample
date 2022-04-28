package test.java.security

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * https://en.wikipedia.org/wiki/Key_derivation_function
 */
@Deprecated(message = "!")
object KDFUtil {
    fun derive(
        password: CharArray,
        size: Int, // bytes
        params: KDFParams
    ): ByteArray {
        when (params) {
            is KDFParams.PBKDF2 -> {
                val spec = PBEKeySpec(password, params.salt, params.iterations, size)
                val algorithm = when (params.type) {
                    KDFParams.PBKDF2.Type.HMAC_SHA256 -> "PBKDF2WithHmacSHA256"
                }
                val factory = SecretKeyFactory.getInstance(algorithm)
                return factory.generateSecret(spec).encoded
            }
        }
    }
}

@Deprecated(message = "!")
sealed interface KDFParams {
    class PBKDF2(
        val type: Type,
        val salt: ByteArray,
        val iterations: Int
    ) : KDFParams {
        enum class Type {
            HMAC_SHA256
        }
    }
}
