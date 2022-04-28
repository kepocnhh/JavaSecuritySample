package test.java.security

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

fun main() {
    Security.addProvider(BouncyCastleProvider())
    val provider = BouncyCastleProvider.PROVIDER_NAME
//    val decrypted = "Hello java security!"
//    println("input: $decrypted")
//    CipherSample.check(provider = provider, decrypted = decrypted)
//    MessageDigestSample.check(provider = provider, decrypted = decrypted)
//    MacSample.check(provider = provider, decrypted = decrypted)
//    SignatureSample.check(provider = provider, decrypted = decrypted)
//    KeyPairSample.check(provider = provider)
//    CertificateSample.check(provider = provider)
//    KeyStoreSample.check(provider = provider)
    AsymmetricSample.run(provider = provider)
}
