package burp

import burp.model.PayloadPart
import burp.model.code

class CookieInsertionPointProvider(
    private val helpers: IExtensionHelpers,
) : IScannerInsertionPointProvider {

    private val cookieStub = helpers.buildParameter(INSERTION_PATTERN1.decodeToString(), "1", IParameter.PARAM_COOKIE)

    override fun getInsertionPoints(baseRequestResponse: IHttpRequestResponse): List<IScannerInsertionPoint> {
        val insertionPoints = mutableListOf<IScannerInsertionPoint>()
        val request = helpers.addParameter(baseRequestResponse.request, cookieStub)

        var from = 0
        val end = findEnd(request)

        while (true) {
            from = helpers.indexOfR(request, INSERTION_PATTERN1, false, from, end)
            if (from == -1) break
            insertionPoints.add(RawInsertionPoint(request, INSERTION_POINT_NAME, from - INSERTION_PATTERN1.size, from))
        }

        return insertionPoints
    }

    private fun findEnd(request: ByteArray): Int {
        return helpers.indexOfR(request, INSERTION_PATTERN2, false, 0, request.size)
    }

    companion object {
        val INSERTION_POINT_NAME = "${PayloadPart.NameCookie.code}|"

        private val INSERTION_PATTERN1 = clazz<CookieInsertionPointProvider>().name.toByteArray()
        private val INSERTION_PATTERN2 = "\r\n\r\n".toByteArray()
    }
}
