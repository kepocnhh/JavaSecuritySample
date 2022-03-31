package test.java.security

import java.security.Key
import java.security.SecureRandom
import javax.crypto.KeyGenerator

object KeyGeneratorUtil {
    fun generateKey(algorithm: String, size: Int, random: SecureRandom): Key {
        val generator = KeyGenerator.getInstance(algorithm)
        generator.init(size, random)
        return generator.generateKey()
    }
}
