package test.java.security

fun ByteArray.print() {
    val d = 4
    val map = mapIndexed { index, byte -> index to byte }.groupBy { (index, _) -> index / d }
    val blocks = map.map { (k, v) -> "${String.format("%2d", k)}|" + v.joinToString(separator = "|") { (_, byte) -> String.format("%4d", byte) }}
    println("  |" + (0 until d).joinToString(separator = "|") { String.format("%4d", it) })
    println("--+" + (0 until d).joinToString(separator = "+") { "----" })
    println(blocks.joinToString(separator = "\n"))
}
