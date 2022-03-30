package test.java.security

import java.security.Key
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

object CipherSample {
    fun check(decrypted: String) {
        println("input: $decrypted")
        val algorithm = "AES"
        val random = SecureRandom()
        val key = key(algorithm = algorithm, random)
        val params = params(random)
        val cipher = cipher(algorithm = algorithm)
        val encrypted = cipher.encrypt(
            key = key,
            params = params,
            decrypted = decrypted.toByteArray(Charsets.UTF_8)
        )
        val result = cipher.decrypt(
            key = key,
            params = params,
            encrypted = encrypted
        )
        val decoded = String(result, Charsets.UTF_8)
        println("output: $decoded")
        check(decrypted == decoded)
    }

    private fun cipher(algorithm: String): Cipher {
        /**
         * EBC — Electronic Codebook
         * CBC — Cipher Block Chaining
         * CFB — Cipher Feedback
         * OFB — Output Feedback
         * CTR — Counter
         */
        val blockMode = "CBC"
        /**
         * NoPadding
         * PKCS1Padding
         * PKCS5Padding
         * PKCS7Padding
         * OAEPWithSHA-1AndMGF1Padding
         * OAEPWithSHA-256AndMGF1Padding
         */
        val paddings = "PKCS7Padding"
        val transformation = "$algorithm/$blockMode/$paddings"
        return Cipher.getInstance(transformation)
    }

    private fun key(algorithm: String, random: SecureRandom): Key {
        val generator = KeyGenerator.getInstance(algorithm)
        val size = 256
        generator.init(size, random)
        return generator.generateKey()
    }

    private fun params(random: SecureRandom): AlgorithmParameterSpec {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return IvParameterSpec(bytes)
    }

    private fun encrypt(algorithm: String, key: Key, params: AlgorithmParameterSpec, decrypted: ByteArray): ByteArray {
        val cipher = cipher(algorithm = algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key, params)
        return cipher.doFinal(decrypted)
    }

    private fun decrypt(algorithm: String, key: Key, params: AlgorithmParameterSpec, encrypted: ByteArray): ByteArray {
        val cipher = cipher(algorithm = algorithm)
        cipher.init(Cipher.DECRYPT_MODE, key, params)
        return cipher.doFinal(encrypted)
    }

    private fun Cipher.encrypt(key: Key, params: AlgorithmParameterSpec, decrypted: ByteArray): ByteArray {
        init(Cipher.ENCRYPT_MODE, key, params)
        return doFinal(decrypted)
    }

    private fun Cipher.decrypt(key: Key, params: AlgorithmParameterSpec, encrypted: ByteArray): ByteArray {
        init(Cipher.DECRYPT_MODE, key, params)
        return doFinal(encrypted)
    }
}
