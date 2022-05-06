package burp

import burp.model.PayloadPart
import burp.model.code

class UrlRawInsertionPointProvider(
    private val helpers: IExtensionHelpers,
) : IScannerInsertionPointProvider {

    private val urlStub = helpers.buildParameter(INSERTION_PATTERN1.decodeToString(), "1", IParameter.PARAM_URL)

    override fun getInsertionPoints(baseRequestResponse: IHttpRequestResponse): List<IScannerInsertionPoint> {
        val insertionPoints = mutableListOf<IScannerInsertionPoint>()
        val request = helpers.addParameter(baseRequestResponse.request, urlStub)

        var from = 0
        val end = findEnd(request)

        while (true) {
            from = helpers.indexOfR(request, INSERTION_PATTERN1, false, from, end)
            if (from == -1) break
            insertionPoints.add(RawInsertionPoint(INSERTION_POINT_NAME, request, from - INSERTION_PATTERN1.size, from))
        }

        return insertionPoints
    }

    private fun findEnd(request: ByteArray): Int {
        return helpers.indexOfR(request, INSERTION_PATTERN2, false, 0, request.size)
    }

    companion object {
        val INSERTION_POINT_NAME = "${PayloadPart.NameUrlRaw.code}|"

        private val INSERTION_PATTERN1 = clazz<UrlRawInsertionPointProvider>().name.toByteArray()
        private val INSERTION_PATTERN2 = " HTTP".toByteArray()
    }
}
