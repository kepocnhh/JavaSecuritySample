package test.java.security

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

fun main() {
    Security.addProvider(BouncyCastleProvider())
    val provider = BouncyCastleProvider.PROVIDER_NAME
    val decrypted = "Hello java security!"
    println("input: $decrypted")
//    CipherSample.check(decrypted = decrypted)
    MessageDigestSample.check(provider = provider, decrypted = decrypted)
    MacSample.check(provider = provider, decrypted = decrypted)
}
