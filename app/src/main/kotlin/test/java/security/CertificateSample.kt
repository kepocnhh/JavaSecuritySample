package test.java.security

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.math.BigInteger
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.util.Locale

object CertificateSample {
    fun check(provider: String) {
        val random = SecureRandom.getInstanceStrong()
        val pair = KeyPairGeneratorUtil.generateKeyPair(
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
        val builder = CertificateUtil.builder(
            issuer = X500Name("CN=root/issuer"),
            subject = X500Name("CN=root/subject"),
            serial = BigInteger(64, random),
            notBefore = System.currentTimeMillis(),
            validity = 365L * 24 * 60 * 60 * 1_000, // milliseconds in one year
            locale = Locale.US,
            info = SubjectPublicKeyInfo.getInstance(pair.public.encoded)
        )
        return builder.build(
            algorithm = "SHA512WITHRSA",
            key = pair.private
        ).encoded
    }
}
