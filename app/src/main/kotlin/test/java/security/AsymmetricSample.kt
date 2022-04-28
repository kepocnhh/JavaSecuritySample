package test.java.security

import java.security.SecureRandom

object AsymmetricSample {
    fun run(provider: String) {
        val random = SecureRandom.getInstanceStrong()
        val algorithm = "RSA"
        val pair = KeyPairGeneratorUtil.generateKeyPair(
            provider = provider,
            algorithm = algorithm,
            size = 2048, // bits == 256 bytes
            random = random
        )
//        val decrypted = "Hello java security!"
        val cipher = CipherUtil.getInstance(
            provider = provider,
            algorithm = algorithm,
            blockMode = "ECB",
            paddings = "PKCS1Padding"
        )
//        val encoded = decrypted.toByteArray(Charsets.UTF_8)
//        val size = 245
        val size = 246
        val encoded = random.nextBytes(size)
        val encrypted = cipher.encrypt(
            key = pair.public,
            decrypted = encoded
        )
        check(encoded.contentEquals(cipher.decrypt(key = pair.private, encrypted = encrypted)))
    }
}
