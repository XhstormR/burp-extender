package burp

import burp.model.PayloadPart
import burp.model.code

class HeaderInsertionPointProvider(
    private val helpers: IExtensionHelpers,
) : IScannerInsertionPointProvider {

    override fun getInsertionPoints(baseRequestResponse: IHttpRequestResponse): List<IScannerInsertionPoint> {
        val insertionPoints = mutableListOf<IScannerInsertionPoint>()
        val request = baseRequestResponse.request

        var from = 0
        val end = findEnd(request)

        while (true) {
            from = helpers.indexOfR(request, INSERTION_PATTERN1, false, from, end)
            if (from == -1) break
            val to = helpers.indexOf(request, INSERTION_PATTERN2, false, from, end)
            insertionPoints.add(RawInsertionPoint(INSERTION_POINT_NAME, request, from, to))
        }

        return insertionPoints
    }

    private fun findEnd(request: ByteArray): Int {
        return helpers.indexOfR(request, INSERTION_PATTERN3, false, 0, request.size)
    }

    companion object {
        val INSERTION_POINT_NAME = "${PayloadPart.Header.code}|Origin"

        private val INSERTION_PATTERN1 = "Origin: ".toByteArray()
        private val INSERTION_PATTERN2 = "\r\n".toByteArray()
        private val INSERTION_PATTERN3 = "\r\n\r\n".toByteArray()
    }
}
