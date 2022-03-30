package test.java.security

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

fun sampleCipherGetInstance() {
    val algorithm = "AES"
    val blockMode = "CBC"
    val paddings = "PKCS7Padding"
    val transformation = "$algorithm/$blockMode/$paddings"
    val cipher = Cipher.getInstance(transformation)
}

private fun secretKey(bytes: ByteArray, algorithm: String): SecretKey {
    return SecretKeySpec(bytes, algorithm)
}

fun sampleCipherInitEncrypt(cipher: Cipher) {
    val bytes = byteArrayOf(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
    val key = secretKey(bytes = bytes, algorithm = "RawBytes")
    cipher.init(Cipher.ENCRYPT_MODE, key)
}

fun sampleKeyGenerator() {
    val algorithm = "AES"
    val generator = KeyGenerator.getInstance(algorithm)
    val size = 256
    generator.init(size, SecureRandom())
    val key = generator.generateKey()
}

private fun keyPair(algorithm: String): KeyPair {
    val generator = KeyPairGenerator.getInstance(algorithm)
    return generator.generateKeyPair()
}

fun sampleKeyPairGenerator() {
    val algorithm = "DSA"
    val generator = KeyPairGenerator.getInstance(algorithm)
    val pair = generator.generateKeyPair()
}

fun sampleMessageDigest() {
    val algorithm = "SHA-256"
    val digest = MessageDigest.getInstance(algorithm)
    val one = digest.digest("0123456789".toByteArray(Charsets.UTF_8))
    digest.update("0123456789".toByteArray(Charsets.UTF_8))
    digest.update("abcdefghijklmnopqrstuvxyz".toByteArray(Charsets.UTF_8))
    val two = digest.digest()
}

fun sampleMac() {
    val algorithm = "HmacSHA256"
    val mac = Mac.getInstance(algorithm)
    val bytes = byteArrayOf(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
    val key = secretKey(bytes = bytes, algorithm = "RawBytes")
    mac.init(key)
    val one = mac.doFinal("0123456789".toByteArray(Charsets.UTF_8))
    mac.update("0123456789".toByteArray(Charsets.UTF_8))
    mac.update("abcdefghijklmnopqrstuvxyz".toByteArray(Charsets.UTF_8))
    val two = mac.doFinal()
}

private fun sign(algorithm: String, key: PrivateKey, bytes: ByteArray): ByteArray {
    val signature = Signature.getInstance(algorithm)
    signature.initSign(key, SecureRandom())
    signature.update(bytes)
    return signature.sign()
}

private fun verify(algorithm: String, key: PublicKey, bytes: ByteArray, sign: ByteArray): Boolean {
    val signature = Signature.getInstance(algorithm)
    signature.initVerify(key)
    signature.update(bytes)
    return signature.verify(sign)
}

fun sampleSignature() {
    val algorithm = "SHA256WithDSA"
    val encoded = "0123456789"
    val keyPair = keyPair(algorithm = "DSA")
    val sign = sign(
        algorithm = algorithm,
        key = keyPair.private,
        bytes = encoded.toByteArray(Charsets.UTF_8)
    )
    check(verify(algorithm = algorithm, key = keyPair.public, bytes = encoded.toByteArray(Charsets.UTF_8), sign = sign))
}
