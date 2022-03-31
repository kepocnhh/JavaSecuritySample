package test.java.security

import java.security.Key
import java.security.SecureRandom
import javax.crypto.KeyGenerator

object KeyGeneratorUtil {
    fun generateKey(algorithm: String, random: SecureRandom): Key {
        val generator = KeyGenerator.getInstance(algorithm)
        val size = 256
        generator.init(size, random)
        return generator.generateKey()
    }
}
