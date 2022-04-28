package test.java.security

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

fun ByteArray.toSecretKey(algorithm: String): SecretKey {
    return SecretKeySpec(this, algorithm)
}
