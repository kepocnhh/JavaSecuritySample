package test.java.security

import java.security.SecureRandom
import javax.crypto.Mac

object MacSample {
    fun check(provider: String, decrypted: String) {
        /**
         * HmacMD5
         * HmacSHA1
         * HmacSHA256
         */
        val algorithm = "HmacSHA256"
        val mac = Mac.getInstance(algorithm, provider)
        val random = SecureRandom()
        val key = KeyGeneratorUtil.generateKey(algorithm = "AES", size = 256, random)
//        val params = AlgorithmParameterSpecUtil.create(random)
//        mac.init(key, params)
        mac.init(key)
        val result = mac.doFinal(decrypted.toByteArray(Charsets.UTF_8))
        println("$algorithm:")
        result.print()
    }
}
