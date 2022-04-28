package test.java.security

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec

object KeyPairGeneratorUtil {
    fun generateKeyPair(provider: String, algorithm: String, size: Int, random: SecureRandom): KeyPair {
        val generator = KeyPairGenerator.getInstance(algorithm, provider)
        generator.initialize(size, random)
        return generator.generateKeyPair()
    }

    fun generateKeyPair(provider: String, algorithm: String, params: AlgorithmParameterSpec): KeyPair {
        val generator = KeyPairGenerator.getInstance(algorithm, provider)
        generator.initialize(params)
        return generator.generateKeyPair()
    }
}
