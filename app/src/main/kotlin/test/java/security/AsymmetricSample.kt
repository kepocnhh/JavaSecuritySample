package test.java.security

import org.bouncycastle.jce.spec.IESParameterSpec
import org.bouncycastle.util.encoders.Base64Encoder
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

object AsymmetricSample {
    /**
     * ECIES
     * ECIESWithAES-CBC
     * ECIESWithDESEDE-CBC
     * ECIESWithSHA1
     * ECIESWithSHA1ANDAES-CBC
     * ECIESWithSHA1ANDDESEDE-CBC
     * ECIESWithSHA256
     * ECIESWithSHA256ANDAES-CBC
     * ECIESWithSHA256ANDDESEDE-CBC
     * ECIESWithSHA384
     * ECIESWithSHA384ANDAES-CBC
     * ECIESWithSHA384ANDDESEDE-CBC
     * ECIESWithSHA512
     * ECIESWithSHA512ANDAES-CBC
     * ECIESWithSHA512ANDDESEDE-CBC
     */
    fun run(provider: String) {
//        val algorithms = Security.getAlgorithms("ECGenParameterSpec")
//        val algorithms = Security.getAlgorithms("Signature")
//        println("algorithms: " + algorithms.sorted().joinToString(separator = "\n"))
//        return
        val random = SecureRandom.getInstanceStrong()
        val encoder = Base64Encoder()
//        val iv = random.nextBytes(16)
        val AE_TYPE = "EC"
        /**
         * EC
         * ECDH
         * ECDHC
         * ECDHWITHSHA1KDF
         * ECDSA
         * ECGOST3410
         * ECGOST3410-2012
         * ECIES
         * ECMQV
         */
//        val algorithm = "EC"
        /**
         * https://datatracker.ietf.org/doc/html/rfc5639#section-3
         */
//        val size = 160 // Key length 160../256../512 bits
        val size = 256
//        val size = 512
//        val name = "brainpoolP160r1" // 160-Bit
//        val name = "brainpoolP320t1" // Twisted
        val name = "brainpool".let {
            val type = "r"
            "${it}P${size}${type}1"
        }
        /**
         * https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.524.9390&rep=rep1&type=pdf
         */
//        val name = "sect163k1"
//        val name = "sect239k1"
//        val name = "sect283r1"
        val HASH_TYPE = "SHA$size"
        val pair = KeyPairGeneratorUtil.generateKeyPair(
            provider = provider,
            algorithm = AE_TYPE,
            params = ECGenParameterSpec(name)
        )
        println("public [${pair.public.encoded.size}]: " + encoder.encode(pair.public.encoded, Charsets.UTF_8))
        println("private [${pair.private.encoded.size}]: " + encoder.encode(pair.private.encoded, Charsets.UTF_8))
//        val cipher = Cipher.getInstance("ECIESWithAES-CBC", provider)
        val cipher = Cipher.getInstance("${AE_TYPE}IESWith${HASH_TYPE}AndAES-CBC", provider) // Key length 128/192/256 bits
        val decrypted = "Hello java security!"
        val encoded = decrypted.toByteArray(Charsets.UTF_8)
        println("expected [${encoded.size}]: " + encoder.encode(encoded, Charsets.UTF_8))
        /**
         * SHA256WithCVC-ECDSA
         * SHA256WithDDSA
         * SHA256WithDETDSA
         * SHA256WithDSA
         * SHA256WithDSAINP1363FORMAT
         * SHA256WithECDDSA
         * SHA256WithECDSA
         * SHA256WithECDSAINP1363FORMAT
         * SHA256WithECNR
         * SHA256WithPLAIN-ECDSA
         * SHA256WithRSA
         * SHA256WithRSA/ISO9796-2
         * SHA256WithRSA/X9.31
         * SHA256WithRSAANDMGF1
         * SHA256WithRSAANDSHAKE128
         * SHA256WithRSAANDSHAKE256
         * SHA256WithSM2
         */
        val signature = Signature.getInstance("${HASH_TYPE}With${AE_TYPE}DSA", provider)
        val signed = signature.sign(
            key = pair.private,
            random = random,
            decrypted = encoded
        )
        println("signed [${signed.size}]: " + encoder.encode(signed, Charsets.UTF_8))
//        val size = 245
//        val size = 246
//        val encoded = random.nextBytes(size)
//        val params = IvParameterSpec(iv)
        val params = IESParameterSpec(
            random.nextBytes(16),
            random.nextBytes(16),
            size,
            size,
            random.nextBytes(16)
        )
        val encrypted = cipher.encrypt(
            key = pair.public,
            params = params,
            decrypted = encoded
        )
        println("encrypted [${encrypted.size}]: " + encoder.encode(encrypted, Charsets.UTF_8))
        val actual = cipher.decrypt(
            key = pair.private,
            params = params,
            encrypted = encrypted
        )
        println("actual [${actual.size}]: " + encoder.encode(actual, Charsets.UTF_8))
        check(encoded.contentEquals(actual))
        check(signature.verify(key = pair.public, decrypted = encoded, signed = signed))
    }

    fun runRSA(provider: String) {
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
