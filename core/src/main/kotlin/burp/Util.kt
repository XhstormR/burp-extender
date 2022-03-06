package burp

import kotlin.random.Random

fun Long.between(i: Long, j: Long) = this in i..j

inline fun <reified T> clazz() = T::class.java

inline fun <R> measureTimeMillisWithResult(block: () -> R): Pair<R, Long> {
    val start = System.currentTimeMillis()
    val result = block()
    return result to (System.currentTimeMillis() - start)
}

private val LOWER_CHARS = 'a'..'z'

fun randomString(length: Int) = generateSequence { LOWER_CHARS.random() }
    .take(length)
    .joinToString("")

fun randomInt(from: Int, until: Int) =
    Random.nextInt(from, until)

fun randomDouble(from: Double, until: Double) =
    Random.nextDouble(from, until)

fun List<IntArray>.merge(): List<IntArray> {
    val ret = mutableListOf<IntArray>()
    val sorted = this.sortedBy { it[0] }
    var i = 0
    val j = sorted.size
    var temp: IntArray? = null
    while (i < j) {
        if (i + 1 != j && sorted[i][1] >= sorted[i + 1][0]) {
            temp = intArrayOf(temp?.get(0) ?: sorted[i][0], sorted[i + 1][1])
        } else {
            ret.add(temp ?: sorted[i])
            temp = null
        }
        i++
    }
    return ret
}
