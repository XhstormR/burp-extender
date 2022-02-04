package io.github.xhstormr.burp.core

import java.io.InputStream
import java.io.SequenceInputStream
import java.nio.charset.Charset
import java.nio.file.Path
import java.util.Collections
import kotlin.io.path.Path
import kotlin.io.path.createTempFile
import kotlin.io.path.inputStream
import kotlin.io.path.isRegularFile
import kotlin.io.path.writeLines
import kotlin.io.path.writeText
import kotlin.random.Random

fun getCurrentJar(): Path =
    Path.of(clazz<BurpExtender>().protectionDomain.codeSource.location.toURI())

fun getSystemResource(name: String): Path =
    Path.of(ClassLoader.getSystemResource(name).toURI())

fun getSystemResourceAsStream(name: String): InputStream? =
    ClassLoader.getSystemResourceAsStream(name)

fun getFileInputStream(pathname: String) =
    getFileInputStream(Path(pathname))

fun getFileInputStream(file: Path) =
    file.takeIf { it.isRegularFile() }?.inputStream()

fun writeTempFile(text: String) = createTempFile()
    .apply { writeText(text) }

fun writeTempFile(texts: Collection<String>) = createTempFile()
    .apply { writeLines(texts) }

fun readProcessOutput(command: String) = ProcessBuilder(command.split(" "))
    .redirectErrorStream(true)
    .start()
    .inputStream
    .bufferedReader()
    .useLines { it.toSet() }

fun String.toHexString(charset: Charset) = this
    .toByteArray(charset)
    .joinToString("") { """\x%02x""".format(it) }

private val BOUNDARY_REGEX = """[^\w\u4E00-\u9FA5]""".toRegex()

fun Long.between(i: Long, j: Long) = this in i..j

fun Char.isAscii() = code in 0..127

fun Char.isChinese() = Character.UnicodeScript.of(code) == Character.UnicodeScript.HAN

fun Char.isBoundary() = BOUNDARY_REGEX.matches(this.toString())

fun Char.toHalfWidth() = when (code) {
    12288 -> Char(32)
    in 65280..65375 -> Char(code - 65248)
    else -> this
}

fun Char.toFullWidth() = when (code) {
    32 -> Char(12288)
    in 0..127 -> Char(code + 65248)
    else -> this
}

fun CharSequence.isWord(begin: Int, end: Int): Boolean {
    if (begin != 0 && !this[begin - 1].isBoundary()) return false
    if (end != length && !this[end].isBoundary()) return false
    return true
}

fun StringBuilder.replaceWithChar(range: IntRange, ch: Char) = apply { range.forEach { setCharAt(it, ch) } }

inline fun <reified T> clazz() = T::class.java

inline fun <R> measureTimeMillisWithResult(block: () -> R): Pair<R, Long> {
    val start = System.currentTimeMillis()
    val result = block()
    return result to (System.currentTimeMillis() - start)
}

operator fun InputStream.plus(inputStream: InputStream) =
    SequenceInputStream(Collections.enumeration(listOf(this, inputStream)))

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
