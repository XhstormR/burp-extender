package burp.spel

import burp.HttpRequestResponseWrapper
import burp.IExtensionHelpers
import burp.randomDouble as randomDoubleA
import burp.randomInt as randomIntA
import burp.randomString as randomStringA

data class HttpObject(
    val http: HttpRequestResponseWrapper,
    val helpers: IExtensionHelpers,
) {

    val request = http.requestInfoWrapper
    val response = http.responseInfoWrapper

    fun isA(x: Any): Boolean {
        println("isA")
        println(x)
        return true
    }

    fun md5(x: Any): Boolean {
        println("md5")
        println(x)
        return true
    }

    fun abc(response: HttpRequestResponseWrapper.ResponseInfoWrapper): Boolean {
        println("abc")
        println(response)
        return true
    }

    fun randomString(length: Int) = randomStringA(length)

    fun randomInt(from: Int, until: Int) = randomIntA(from, until)

    fun randomDouble(from: Double, until: Double) = randomDoubleA(from, until)
}
