package test.java.security

import java.security.SecureRandom
import java.security.Signature

object SignatureSample {
    fun check(provider: String, decrypted: String) {
        /**
         * NONEwithRSA
         * MD2withRSA
         * ...
         * SHA1withRSA
         * ...
         * SHA3-224withRSA
         * ...
         * https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html#signature-algorithms
         */
        val algorithm = "SHA256WithDSA"
        val signature = Signature.getInstance(algorithm, provider)
        val random = SecureRandom()
        val pair = KeyPairGeneratorUtil.generateKeyPair(
            provider = provider,
            algorithm = "DSA",
            size = 1024 * 2,
            random = random
        )
        val signed = signature.sign(
            key = pair.private,
            random = random,
            decrypted = decrypted.toByteArray(Charsets.UTF_8)
        )
        check(signature.verify(key = pair.public, decrypted = decrypted.toByteArray(Charsets.UTF_8), signed = signed))
    }
}
