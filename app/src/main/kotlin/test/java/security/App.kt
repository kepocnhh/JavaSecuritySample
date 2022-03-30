package test.java.security

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

fun main() {
    Security.addProvider(BouncyCastleProvider())
    val decrypted = "Hello java security!"
//    CipherSample.check(decrypted = decrypted)
    MessageDigestSample.check(decrypted = decrypted)
}
