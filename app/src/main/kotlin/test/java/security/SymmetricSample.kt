package test.java.security

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.util.encoders.Base64Encoder
import java.security.SecureRandom
import java.security.Security
import java.security.spec.AlgorithmParameterSpec
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import kotlin.math.pow

object SymmetricSample {
    fun run(provider: String) {
//        val algorithms = Security.getAlgorithms("Cipher")
//        println("algorithms: " + algorithms.sorted().joinToString(separator = "\n"))
//        return
        val password = "4"
        val decrypted = "Hello java security!"
        val random = SecureRandom.getInstanceStrong()
        val encoder = Base64Encoder()
        val salt = random.nextBytes(32)
        val iv = random.nextBytes(16)
//        val params: AlgorithmParameterSpec = IvParameterSpec(iv)
        /**
         *  The GCM specification states that tLen may only have the values {128, 120, 112, 104, 96}, or {64, 32} for certain applications.
         *  Other values can be specified for this class, but not all CSP implementations will support them.
        */
        val params: AlgorithmParameterSpec = GCMParameterSpec(128, iv)
        val additional = random.nextBytes(32)
        val secret = random.nextBytes(32)
//        val size = 16
        val size = 32 // 256 bits
//        val iterations = 2 // 2^1
        val iterations = 8 // 2^3
//        val iterations = 16 // 2^4
//        val iterations = 32 // 2^5
//        val iterations = 64 // 2^6
//        val iterations = 1024 // 2^10
//        val iterations = 131_072 // 2^17
//        val iterations = 262144 // 2^18
//        val iterations = 1_048_576 // 2^20
        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_10)
            .withIterations(iterations)
            .withMemoryPowOfTwo(16)
            .withParallelism(1)
            .withAdditional(additional)
            .withSecret(secret)
            .withSalt(salt)
        val generator = Argon2BytesGenerator()
        generator.init(builder.build())
        val algorithm = "AES"
        val key = ByteArray(size).also {
            generator.generateBytes(password.toCharArray(), it)
        }.toSecretKey(algorithm) // 128/192/256 bits
        println("key: " + key.encoded.size)
        val cipher = CipherUtil.getInstance(
            provider = provider,
            algorithm = algorithm,
            blockMode = "GCM",
            paddings = "NoPadding"
        )
        val encoded = decrypted.toByteArray(Charsets.UTF_8)
        val encrypted = cipher.encrypt(
            key = key,
            params = params,
            decrypted = encoded
        )
        println("encrypted [${encrypted.size}]: " + encoder.encode(encrypted, Charsets.UTF_8))
        cipher.decrypt(
            key = key,
            params = params,
            encrypted = encrypted
        ).also { d ->
            check(encoded.contentEquals(d))
            println("decrypted [${d.size}]: " + encoder.encode(d, Charsets.UTF_8))
        }
        val time = System.nanoTime()
//        val iva = iv
        val iva = random.nextBytes(16)
        val ps: AlgorithmParameterSpec = GCMParameterSpec(128, iva)
        for (i in 0 until 32) {
            val p = i.toString()
            val t = System.nanoTime()
            val k = ByteArray(size).also {
                generator.generateBytes(p.toCharArray(), it)
            }.toSecretKey(algorithm)
            val d = try {
                cipher.decrypt(key = k, params = ps, encrypted = encrypted)
            } catch (e: Throwable) {
                println("$i... " + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t) + " millis")
                println("error: $e")
                continue
            }
            check(encoded.contentEquals(d)) {
                """
                    |
                    actual: $p
                    expected: $password
                    decrypted start: ${encoder.encode(encoded, Charsets.UTF_8)}
                    decrypted finish: ${encoder.encode(d, Charsets.UTF_8)}
                """.trimIndent()
            }
            val nanoseconds = System.nanoTime() - time
            println("time: " + TimeUnit.NANOSECONDS.toSeconds(nanoseconds) + " seconds")
            println(" - " + TimeUnit.NANOSECONDS.toMillis(nanoseconds / (i + 1)) + " millis per decrypt")
            break
        }
    }

    fun run1(provider: String) {
//        val r = 100 * 10.0.pow(6)
//        println("hours: " + TimeUnit.MILLISECONDS.toHours(r.toLong()))
//        TODO()
        val password = "16"
        val decrypted = "Hello java security!"
        val random = SecureRandom.getInstanceStrong()
        val encoder = Base64Encoder()
//        val salt = random.nextBytes(8)
//        val salt = random.nextBytes(32)
        val salt = encoder.decode("UPbyFrAe+0c+H8naVHrk+X4lGUKlnwq0pfPGn3cMlrw=")
//        val iv = random.nextBytes(16)
        val iv = encoder.decode("EfQpjRSWdEwUskXNMKSNNg==")
        val algorithm = "PBEWITHHMACSHA256ANDAES_128"
        val encoded = decrypted.toByteArray(Charsets.UTF_8)
        val factory = SecretKeyFactory.getInstance(algorithm)
        val size = 256
//        val size = 2048
//        val iterations = 1024 // 2^10
//        val iterations = 131_072 // 2^17
//        val iterations = 262144 // 2^18
        val iterations = 1_048_576 // 2^20
        val params: AlgorithmParameterSpec = PBEParameterSpec(salt, iterations, IvParameterSpec(iv))
        val cipher = Cipher.getInstance(algorithm)
        val encrypted = cipher.encrypt(
            key = factory.generateSecret(PBEKeySpec(password.toCharArray(), salt, iterations, size)),
            params = params,
            decrypted = encoded
        )
        check(
            encoded.contentEquals(
                cipher.decrypt(
                    key = factory.generateSecret(PBEKeySpec(password.toCharArray(), salt, iterations, size)),
                    params = params,
                    encrypted = encrypted
                )
            )
        )
//        return
        val time = System.nanoTime()
//        val diff = "0987654321".length
//        val diff = "0987654321abcdef".length
        val diff = "0987654321abcdefghiklmnopqrstvxyzABCDEFGHIKLMNOPQRSTVXYZ".length
        val difficult = diff.toDouble().pow(4).toInt()
        for (i in 0 until 32) {
            val p = i.toString()
            val t = System.nanoTime()
            val k = factory.generateSecret(PBEKeySpec(p.toCharArray(), salt, iterations, size))
            val d = try {
                cipher.decrypt(key = k, params = params, encrypted = encrypted)
            } catch (e: Throwable) {
                val iteration = i % 8
                if (iteration == 0) {
                    println("$i... " + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t) + " millis")
                }
                continue
            }
            println("actual: $p")
            println("iteration: $i")
            check(encoded.contentEquals(d)) {
                """
                    -
                    expected: $password
                    salt: ${encoder.encode(salt, Charsets.UTF_8)}
                    iv: ${encoder.encode(iv, Charsets.UTF_8)}
                    iterations: $iterations
                    size: $size
                    -
                    source: "$decrypted"
                    result: "${String(d, Charsets.UTF_8)}"
                """.trimIndent()
            }
            val nanoseconds = System.nanoTime() - time
            println("time: " + TimeUnit.NANOSECONDS.toSeconds(nanoseconds) + " seconds")
            println(" - " + TimeUnit.NANOSECONDS.toMillis(nanoseconds / i) + " millis per decrypt")
            println("hours: " + TimeUnit.NANOSECONDS.toHours((nanoseconds / i) * difficult))
            break
        }
    }
}
