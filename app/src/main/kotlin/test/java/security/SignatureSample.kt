package test.java.security

import java.security.PrivateKey
import java.security.PublicKey
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
        val pair = KeyPairGeneratorUtil.generateKey(
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

    private fun Signature.sign(key: PrivateKey, random: SecureRandom, decrypted: ByteArray): ByteArray {
        initSign(key, random)
        update(decrypted)
        return sign()
    }

    private fun Signature.verify(key: PublicKey, decrypted: ByteArray, signed: ByteArray): Boolean {
        initVerify(key)
        update(decrypted)
        return verify(signed)
    }
}
