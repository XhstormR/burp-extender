package burp

import burp.model.PayloadPart
import burp.model.code

/**
GET /{} HTTP/2
GET /v2/{} HTTP/2
GET /v2/pet/{} HTTP/2
GET /v2/pet/123/{} HTTP/2
 */
class PathInsertionPointProvider(
    private val helpers: IExtensionHelpers,
) : IScannerInsertionPointProvider {

    override fun getInsertionPoints(baseRequestResponse: IHttpRequestResponse): List<IScannerInsertionPoint> {
        val insertionPoints = mutableListOf<IScannerInsertionPoint>()
        val request = baseRequestResponse.request

        var from = 0
        var count = 0
        val end = findEnd(request)

        while (true) {
            from = helpers.indexOfR(request, INSERTION_PATTERN1, false, from, end)
            if (from == -1) break
            insertionPoints.add(RawInsertionPoint(request, INSERTION_POINT_NAME.format(++count), from, end))
        }

        return insertionPoints
    }

    private fun findEnd(request: ByteArray): Int {
        val j = helpers.indexOf(request, INSERTION_PATTERN3, false, 0, request.size)
        val k = helpers.indexOf(request, INSERTION_PATTERN2, false, 0, j)
        return if (k == -1) j else k
    }

    companion object {
        val INSERTION_POINT_NAME = "${PayloadPart.PathFile.code}|%s"

        private val INSERTION_PATTERN1 = "/".toByteArray()
        private val INSERTION_PATTERN2 = "?".toByteArray()
        private val INSERTION_PATTERN3 = " HTTP".toByteArray()
    }
}
