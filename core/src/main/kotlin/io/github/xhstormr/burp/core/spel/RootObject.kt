package io.github.xhstormr.burp.core.spel

import burp.IExtensionHelpers
import burp.IHttpRequestResponse
import burp.IResponseInfo
import io.github.xhstormr.burp.core.requestBody
import io.github.xhstormr.burp.core.responseBody
import io.github.xhstormr.burp.core.randomDouble as randomDoubleA
import io.github.xhstormr.burp.core.randomInt as randomIntA
import io.github.xhstormr.burp.core.randomString as randomStringA

data class RootObject(
    val http: IHttpRequestResponse,
    val helpers: IExtensionHelpers,
) {

    val request = helpers.analyzeRequest(http)
    val response = helpers.analyzeResponse(http.response)

    val requestBody = http.requestBody(request.bodyOffset)
    val responseBody = http.responseBody(response.bodyOffset)

    fun isA(x: Any): Boolean {
        request.headers
        response.headers
        request.bodyOffset
        response.bodyOffset
        println(1)
        println(x)
        println(2)
        return true
    }

    fun md5(x: Any): Boolean {
        println("md5:$x")
        return true
    }

    fun abc(response: IResponseInfo): Boolean {
        println("abc")
        return true
    }

    fun randomInt(from: Int, until: Int) = randomIntA(from, until)

    fun randomDouble(from: Double, until: Double) = randomDoubleA(from, until)

    fun randomString(length: Int) = randomStringA(length)
}
