package test.java.security

import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.SecretKey

object CipherUtil {
    fun getInstance(
        provider: String,
        algorithm: String,
        blockMode: String,
        paddings: String
    ): Cipher {
        val transformation = "$algorithm/$blockMode/$paddings"
        return Cipher.getInstance(transformation, provider)
    }
}

fun Cipher.encrypt(
    key: PublicKey,
    decrypted: ByteArray
): ByteArray {
    init(Cipher.ENCRYPT_MODE, key)
    return doFinal(decrypted)
}

fun Cipher.decrypt(
    key: PrivateKey,
    encrypted: ByteArray
): ByteArray {
    init(Cipher.DECRYPT_MODE, key)
    return doFinal(encrypted)
}

fun Cipher.encrypt(
    key: SecretKey,
    params: AlgorithmParameterSpec,
    decrypted: ByteArray
): ByteArray {
    init(Cipher.ENCRYPT_MODE, key, params)
    return doFinal(decrypted)
}

fun Cipher.decrypt(
    key: SecretKey,
    params: AlgorithmParameterSpec,
    encrypted: ByteArray
): ByteArray {
    init(Cipher.DECRYPT_MODE, key, params)
    return doFinal(encrypted)
}
