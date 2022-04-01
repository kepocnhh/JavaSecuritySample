package test.java.security

import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.SecureRandom

object KeyStoreSample {
    fun check(provider: String) {
        /**
         * JKS
         * JCEKS - symmetric
         * PKCS11
         * PKCS12 - asymmetric
         * DKS
         * Windows-MY
         * BKS
         * BCFKS - symmetric
         */
        symmetric(provider = provider, type = "BCFKS")
        asymmetric(provider = provider, type = "PKCS12")
    }

    private fun symmetric(provider: String, type: String) {
        val password = "123abc"
        val alias = "symmetric"
        val random = SecureRandom()
        val key = KeyGeneratorUtil.generateKey(
            provider = provider,
            algorithm = "AES",
            size = 256,
            random = random
        )
        val array = empty(
            provider = provider,
            type = type
        ).let {
            it.setEntry(alias, KeyStore.SecretKeyEntry(key), KeyStore.PasswordProtection(alias.toCharArray()))
            val stream = ByteArrayOutputStream()
            it.store(stream, password.toCharArray())
            stream.toByteArray()
        }
        val store = array.load(
            provider = provider,
            type = type,
            password = password
        )
        val entry = store.getEntry(alias, KeyStore.PasswordProtection(alias.toCharArray()))
        check(entry is KeyStore.SecretKeyEntry)
        check(key == entry.secretKey)
    }

    private fun asymmetric(provider: String, type: String) {
        val password = "123abc"
        val random = SecureRandom()
        val pair = KeyPairGeneratorUtil.generateKey(
            provider = provider,
            algorithm = "DSA",
            size = 1024 * 2,
            random = random
        )
        TODO()
        val array = empty(
            provider = provider,
            type = type
        ).let {
            it.setEntry("private", KeyStore.PrivateKeyEntry(pair.private, emptyArray()), KeyStore.PasswordProtection("private".toCharArray()))
            val stream = ByteArrayOutputStream()
            it.store(stream, password.toCharArray())
            stream.toByteArray()
        }
        val store = array.load(
            provider = provider,
            type = type,
            password = password
        )
        "private".also { alias ->
            val entry = store.getEntry(alias, KeyStore.PasswordProtection(alias.toCharArray()))
            check(entry is KeyStore.PrivateKeyEntry)
            check(pair.private == entry.privateKey)
        }
    }

    private fun empty(provider: String, type: String): KeyStore {
        val store = KeyStore.getInstance(type, provider)
        store.load(null, CharArray(0))
        return store
    }

    private fun ByteArray.load(provider: String, type: String, password: String): KeyStore {
        val store = KeyStore.getInstance(type, provider)
        store.load(inputStream(), password.toCharArray())
        return store
    }
}
