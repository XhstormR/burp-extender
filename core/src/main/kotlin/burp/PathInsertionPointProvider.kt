package burp

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

        var i = 0
        val j = findEnd(request)

        while (true) {
            i = helpers.indexOf(request, INSERTION_PATTERN1, false, i, j)
            if (i == -1) break
            insertionPoints.add(helpers.makeScannerInsertionPoint(INSERTION_POINT_NAME, request, ++i, j))
        }

        return insertionPoints
    }

    private fun findEnd(request: ByteArray): Int {
        val j = helpers.indexOf(request, INSERTION_PATTERN3, false, 0, request.lastIndex)
        val k = helpers.indexOf(request, INSERTION_PATTERN2, false, 0, j)
        return if (k == -1) j else k
    }

    companion object {
        val INSERTION_POINT_NAME = clazz<PathInsertionPointProvider>().name
        val INSERTION_POINT_TYPE = (IScannerInsertionPoint.INS_EXTENSION_PROVIDED + 1).toByte()

        private val INSERTION_PATTERN1 = "/".toByteArray()
        private val INSERTION_PATTERN2 = "?".toByteArray()
        private val INSERTION_PATTERN3 = " HTTP".toByteArray()
    }
}
