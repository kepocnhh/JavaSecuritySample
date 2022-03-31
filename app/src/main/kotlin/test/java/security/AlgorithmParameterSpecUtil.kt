package test.java.security

import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec

object AlgorithmParameterSpecUtil {
    fun create(random: SecureRandom): AlgorithmParameterSpec {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return IvParameterSpec(bytes)
    }
}
