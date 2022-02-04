package io.github.xhstormr.burp.core

import burp.IExtensionHelpers
import burp.IHttpRequestResponse
import burp.IRequestInfo
import burp.IResponseInfo

class HttpRequestResponseWrapper(
    base: IHttpRequestResponse,
    private val helpers: IExtensionHelpers,
) : IHttpRequestResponse by base {

    val requestInfoWrapper: RequestInfoWrapper
    val responseInfoWrapper: ResponseInfoWrapper

    init {
        val requestInfo = helpers.analyzeRequest(this)
        // val requestBody = this.requestBody(requestInfo.bodyOffset)
        // val requestHeader = this.requestHeader(requestInfo.bodyOffset)
        requestInfoWrapper = RequestInfoWrapper(requestInfo, request)

        val responseInfo = helpers.analyzeResponse(this.response)
        // val responseBody = this.responseBody(responseInfo.bodyOffset)
        // val responseHeader = this.responseHeader(responseInfo.bodyOffset)
        responseInfoWrapper = ResponseInfoWrapper(responseInfo, response)
    }

    open inner class Marker(
        val bytes: ByteArray,
        private val bodyOffset: Int,
    ) {
        val markers = mutableListOf<IntArray>()

        val body by lazy { bytes.decodeToString(bodyOffset) }

        val header by lazy { bytes.decodeToString(0, bodyOffset) }

        private fun match(
            data: ByteArray,
            pattern: ByteArray,
            caseSensitive: Boolean,
            from: Int,
            to: Int,
        ): List<IntArray> {
            val matches = mutableListOf<IntArray>()
            var start = from
            while (start < data.size) {
                start = helpers.indexOf(data, pattern, caseSensitive, start, to)
                if (start == -1) break
                matches.add(intArrayOf(start, start + pattern.size))
                start += pattern.size
            }
            return matches
        }

        private fun mark(
            data: ByteArray,
            pattern: ByteArray,
            caseSensitive: Boolean,
            from: Int,
            to: Int,
        ): Boolean {
            val matches = match(data, pattern, caseSensitive, from, to)
            val contain = matches.isNotEmpty()
            if (contain) {
                markers.addAll(matches)
            }
            return contain
        }

        fun markBody(pattern: String, caseSensitive: Boolean) =
            mark(bytes, helpers.stringToBytes(pattern), caseSensitive, bodyOffset, bytes.size)

        fun markHeader(pattern: String, caseSensitive: Boolean) =
            mark(bytes, helpers.stringToBytes(pattern), caseSensitive, 0, bodyOffset)

        fun markBody(regex: Regex): Boolean {
            val result = regex.find(body) ?: return false
            with(result) {
                markers.add(intArrayOf(range.first + bodyOffset, range.last + bodyOffset + 1))
            }
            return true
        }

        fun markHeader(regex: Regex): Boolean {
            val result = regex.find(header) ?: return false
            with(result) {
                markers.add(intArrayOf(range.first, range.last + 1))
            }
            return true
        }
    }

    inner class RequestInfoWrapper(
        base: IRequestInfo,
        bytes: ByteArray,
    ) : IRequestInfo by base,
        Marker(bytes, base.bodyOffset)

    inner class ResponseInfoWrapper(
        base: IResponseInfo,
        bytes: ByteArray,
    ) : IResponseInfo by base,
        Marker(bytes, base.bodyOffset) {

        val type = inferredMimeType.ifEmpty { statedMimeType }

        var time = 0L

        fun checkTime(value: String): Boolean {
            val (i, j) = value.split('-')
                .take(2)
                .map { it.toLong() }
                .let { it[0] to it[1] }
            return time.between(i, j)
        }
    }
}
