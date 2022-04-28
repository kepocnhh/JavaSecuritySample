package test.java.security

import java.security.SecureRandom
import java.util.Random

object SecureRandomUtil {
    fun getInstance(provider: String, algorithm: String): SecureRandom {
        return SecureRandom.getInstance(algorithm, provider)
    }
}

fun Random.nextBytes(size: Int): ByteArray {
    val array = ByteArray(size)
    nextBytes(array)
    return array
}
