package burp

import burp.model.ContentType
import burp.model.code

fun IHttpRequestResponse.requestBody(bodyOffset: Int) = request.sliceArray(bodyOffset..request.lastIndex)
fun IHttpRequestResponse.responseBody(bodyOffset: Int) = response.sliceArray(bodyOffset..response.lastIndex)

fun IHttpRequestResponse.requestBodyString(bodyOffset: Int) = request.decodeToString(bodyOffset)
fun IHttpRequestResponse.responseBodyString(bodyOffset: Int) = response.decodeToString(bodyOffset)

fun IHttpRequestResponse.requestHeader(bodyOffset: Int) = request.sliceArray(0..bodyOffset)
fun IHttpRequestResponse.responseHeader(bodyOffset: Int) = response.sliceArray(0..bodyOffset)

fun IHttpRequestResponse.requestHeaderString(bodyOffset: Int) = request.decodeToString(0, bodyOffset)
fun IHttpRequestResponse.responseHeaderString(bodyOffset: Int) = response.decodeToString(0, bodyOffset)

fun IExtensionHelpers.indexOfL(data: ByteArray, pattern: ByteArray, caseSensitive: Boolean, from: Int, to: Int) =
    indexOf(data, pattern, caseSensitive, from, to)

fun IExtensionHelpers.indexOfR(data: ByteArray, pattern: ByteArray, caseSensitive: Boolean, from: Int, to: Int) =
    indexOf(data, pattern, caseSensitive, from, to).let { if (it == -1) it else it + pattern.size }

fun IRequestInfo.getContentTypeName() = ContentType.values().first { it.code == contentType }.name
