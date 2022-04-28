package test.java.security

import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature

fun Signature.sign(key: PrivateKey, random: SecureRandom, decrypted: ByteArray): ByteArray {
    initSign(key, random)
    update(decrypted)
    return sign()
}

fun Signature.verify(key: PublicKey, decrypted: ByteArray, signed: ByteArray): Boolean {
    initVerify(key)
    update(decrypted)
    return verify(signed)
}
