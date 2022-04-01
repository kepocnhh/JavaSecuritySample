package test.java.security

import java.security.SecureRandom

object SecureRandomUtil {
    fun getInstance(provider: String, algorithm: String): SecureRandom {
        return SecureRandom.getInstance(algorithm, provider)
    }
}
