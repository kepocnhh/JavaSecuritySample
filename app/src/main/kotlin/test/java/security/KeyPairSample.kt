package test.java.security

import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.KeyGenerator

object KeyPairSample {
    fun check(provider: String) {
        val random = SecureRandom()
        symmetric(provider = provider, random = random)
        asymmetric(provider = provider, random = random)
    }

    private fun symmetric(provider: String, random: SecureRandom) {
        val algorithm = "AES"
        val generator = KeyGenerator.getInstance(algorithm, provider)
        val size = 256
        generator.init(size, random)
        val key = generator.generateKey()
        println("symmetric key | algorithm: $algorithm | size: $size")
        key.encoded.print()
    }

    private fun asymmetric(provider: String, random: SecureRandom) {
        val algorithm = "RSA"
        val generator = KeyPairGenerator.getInstance(algorithm, provider)
        val size = 2048
        generator.initialize(size, random)
        val pair = generator.generateKeyPair()
        println("private key:")
        pair.private.print()
        pair.private.encoded.print()
        println("public key:")
        pair.public.print()
        pair.public.encoded.print()
    }
}
