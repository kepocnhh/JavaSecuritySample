package test.java.security

import java.security.MessageDigest

object MessageDigestSample {
    fun check(provider: String, decrypted: String) {
        /**
         * MD2
         * MD5
         * SHA-1
         * SHA-256
         * SHA-384
         * SHA-512
         */
        val algorithm = "SHA-512"
        val md = MessageDigest.getInstance(algorithm, provider)
        println("$algorithm:")
        val result = md.digest(decrypted.toByteArray(Charsets.UTF_8))
        result.print()
    }
}
