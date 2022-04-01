package test.java.security

import java.security.Key

fun Key.print() {
    println("algorithm: $algorithm | format: $format |  size: ${encoded.size}")
}
