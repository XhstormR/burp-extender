package io.github.xhstormr.burp.core

import burp.IExtensionHelpers
import burp.IHttpRequestResponse
import burp.IScannerInsertionPoint
import burp.IScannerInsertionPointProvider

/**
GET /{} HTTP/2
GET /v2/{} HTTP/2
GET /v2/pet/{} HTTP/2
GET /v2/pet/123/{} HTTP/2
*/
class BurpScannerInsertionPointProvider(
    private val helpers: IExtensionHelpers,
) : IScannerInsertionPointProvider {

    override fun getInsertionPoints(baseRequestResponse: IHttpRequestResponse): List<IScannerInsertionPoint> {
        val insertionPoints = mutableListOf<IScannerInsertionPoint>()
        val request = baseRequestResponse.request

        var i = 0
        val j = helpers.indexOf(request, INSERTION_PATTERN2, false, i, request.lastIndex)

        while (true) {
            i = helpers.indexOf(request, INSERTION_PATTERN1, false, i, j)
            if (i == -1) break
            insertionPoints.add(helpers.makeScannerInsertionPoint(javaClass.name, request, ++i, j))
        }

        return insertionPoints
    }

    companion object {
        private val INSERTION_PATTERN1 = "/".toByteArray()
        private val INSERTION_PATTERN2 = " HTTP".toByteArray()
    }
}
