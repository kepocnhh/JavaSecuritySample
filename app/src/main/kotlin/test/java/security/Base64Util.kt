package test.java.security

import org.bouncycastle.util.encoders.Base64Encoder
import java.io.ByteArrayOutputStream
import java.nio.charset.Charset

fun Base64Encoder.encode(decoded: ByteArray): ByteArray {
    return ByteArrayOutputStream().use {
        encode(decoded, 0, decoded.size, it)
        it.toByteArray()
    }
}

fun Base64Encoder.encode(decoded: ByteArray, charset: Charset): String {
    return String(encode(decoded), charset)
}

fun Base64Encoder.decode(encoded: String): ByteArray {
    return ByteArrayOutputStream().use {
        decode(encoded, it)
        it.toByteArray()
    }
}
