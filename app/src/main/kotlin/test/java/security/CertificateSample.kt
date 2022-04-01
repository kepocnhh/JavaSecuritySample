package test.java.security

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.util.Date
import org.bouncycastle.cert.X509v3CertificateBuilder
import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import java.security.KeyPair
import java.security.cert.CertificateFactory
import java.util.Locale

object CertificateSample {
    fun check(provider: String) {
        val random = SecureRandom.getInstanceStrong()
        val pair = KeyPairGeneratorUtil.generateKey(
            provider = provider,
            algorithm = "RSA",
            size = 1024 * 2,
            random = random
        )
        val type = "X.509"
        val factory = CertificateFactory.getInstance(type, provider)
        val holder = getHolder(random = random, pair = pair)
        val certificate = factory.generateCertificate(holder.inputStream())
        certificate.verify(pair.public)
        println("certificate: ${certificate.type}")
        certificate.encoded.print()
    }

    private fun getHolder(random: SecureRandom, pair: KeyPair): ByteArray {
        val issuer = X500Name("CN=root/issuer")
        val serial = BigInteger(64, random)
        val now = System.currentTimeMillis()
        val validity: Long = 365L * 24 * 60 * 60 // seconds in one year
        val locale = Locale.US
        val subject = X500Name("CN=root/subject")
        val info = SubjectPublicKeyInfo.getInstance(pair.public.encoded)
        val builder = X509v3CertificateBuilder(issuer, serial, Date(now), Date(now + validity), locale, subject, info)
        val algorithm = "SHA512WITHRSA"
        val sIdentifier = DefaultSignatureAlgorithmIdentifierFinder().find(algorithm)
        val dIdentifier = DefaultDigestAlgorithmIdentifierFinder().find(sIdentifier)
        val signer = BcRSAContentSignerBuilder(sIdentifier, dIdentifier)
            .build(PrivateKeyFactory.createKey(pair.private.encoded))
        val holder = builder.build(signer)
        return holder.encoded
    }
}
