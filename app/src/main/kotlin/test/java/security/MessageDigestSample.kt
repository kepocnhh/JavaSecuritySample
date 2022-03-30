package test.java.security

import java.security.MessageDigest

object MessageDigestSample {
    fun check(decrypted: String) {
        println("input: $decrypted")
        /**
         * MD2
         * MD5
         * SHA-1
         * SHA-256
         * SHA-384
         * SHA-512
         */
        val algorithm = "SHA-512"
        val md = messageDigest(algorithm = algorithm)
        val result = md.digest(decrypted.toByteArray(Charsets.UTF_8))
        val d = 4
        val map = result.mapIndexed { index, byte -> index to byte }.groupBy { (index, _) -> index / d }
        val blocks = map.map { (k, v) -> "${String.format("%2d", k)}|" + v.joinToString(separator = "|") { (_, byte) -> String.format("%4d", byte) }}
        println("$algorithm:")
        println("  |" + (0 until d).joinToString(separator = "|") { String.format("%4d", it) })
        println("--+" + (0 until d).joinToString(separator = "+") { "----" })
        println(blocks.joinToString(separator = "\n"))
    }

    private fun messageDigest(algorithm: String): MessageDigest {
        return MessageDigest.getInstance(algorithm)
    }
}
