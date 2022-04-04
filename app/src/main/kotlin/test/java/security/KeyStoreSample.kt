package test.java.security

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Locale

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
//        asymmetric(provider = provider, type = "PKCS12")
        val chars = "1234567890qwertyuiopasdfghjklzxcvbnm"
        val random = SecureRandom.getInstanceStrong()
        val keyStorePassword = CharArray(16) {
            chars[random.nextInt(chars.length)]
        }.concatToString()
        val keyAlias = "key|alias"
        val keyPassword = CharArray(16) {
            chars[random.nextInt(chars.length)]
        }.concatToString()
        "BKS".also { type ->
            asymmetric(
                provider = provider,
                type = type,
                keyStorePassword = keyStorePassword,
                keyAlias = keyAlias,
                keyPassword = keyPassword
            )
            local(
                provider = provider,
                type = type,
                keyStorePassword = keyStorePassword,
                keyAlias = keyAlias,
                keyPassword = keyPassword
            )
        }
    }

    private fun local(
        provider: String,
        type: String,
        keyStorePassword: String,
        keyAlias: String,
        keyPassword: String
    ) {
        val factory = KeyFactory.getInstance("RSA", provider)
        val private: PrivateKey = FileInputStream(File("/tmp", "key.private")).use {
            factory.generatePrivate(PKCS8EncodedKeySpec(it.readBytes()))
        }
        val public: PublicKey = FileInputStream(File("/tmp", "key.public")).use {
            factory.generatePublic(X509EncodedKeySpec(it.readBytes()))
        }
        val store = FileInputStream(File("/tmp", "ks.${type.lowercase()}")).use {
            it.readBytes().load(
                provider = provider,
                type = type,
                password = keyStorePassword
            )
        }
        store.check(private = private, public = public, alias = keyAlias, password = keyPassword)
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

    private fun KeyStore.check(private: PrivateKey, public: PublicKey, alias: String, password: String) {
        val entry = getEntry(alias, KeyStore.PasswordProtection(password.toCharArray()))
        check(entry is KeyStore.PrivateKeyEntry)
        check(private == entry.privateKey)
        entry.certificate.verify(public)
    }

    private fun asymmetric(
        provider: String,
        type: String,
        keyStorePassword: String,
        keyAlias: String,
        keyPassword: String
    ) {
        val random = SecureRandom()
        val pair = KeyPairGeneratorUtil.generateKey(
            provider = provider,
            algorithm = "RSA",
            size = 1024 * 2,
            random = random
        )
        File("/tmp", "key.private").also { file ->
            file.delete()
            FileOutputStream(file).use {
                it.write(pair.private.encoded)
            }
        }
        File("/tmp", "key.public").also { file ->
            file.delete()
            FileOutputStream(file).use {
                it.write(pair.public.encoded)
            }
        }
        val builder = CertificateUtil.builder(
            issuer = X500Name("CN=root/issuer"),
            subject = X500Name("CN=root/subject"),
            serial = BigInteger(64, random),
            notBefore = System.currentTimeMillis(),
            validity = 365L * 24 * 60 * 60 * 1_000, // milliseconds in one year
            locale = Locale.US,
            info = SubjectPublicKeyInfo.getInstance(pair.public.encoded)
        )
        val holder = builder.build(
            algorithm = "SHA512WITHRSA",
            key = pair.private
        )
        val certificate = "X.509".let {
            val factory = CertificateFactory.getInstance(it, provider)
            factory.generateCertificate(holder.encoded.inputStream())
        }
        val array = empty(
            provider = provider,
            type = type
        ).let {
            it.setEntry(
                keyAlias,
                KeyStore.PrivateKeyEntry(pair.private, arrayOf(certificate)),
                KeyStore.PasswordProtection(keyPassword.toCharArray())
            )
            val stream = ByteArrayOutputStream()
            it.store(stream, keyStorePassword.toCharArray())
            stream.toByteArray()
        }
        File("/tmp", "ks.${type.lowercase()}").also { file ->
            file.delete()
            FileOutputStream(file).use {
                it.write(array)
            }
        }
        array.load(
            provider = provider,
            type = type,
            password = keyStorePassword
        ).check(private = pair.private, public = pair.public, alias = keyAlias, password = keyPassword)
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
