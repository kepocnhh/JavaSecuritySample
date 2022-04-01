package test.java.security

import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object KeyGeneratorUtil {
    fun generateKey(
        provider: String,
        algorithm: String,
        size: Int,
        random: SecureRandom
    ): SecretKey {
        val generator = KeyGenerator.getInstance(algorithm, provider)
        generator.init(size, random)
        return generator.generateKey()
    }
}
