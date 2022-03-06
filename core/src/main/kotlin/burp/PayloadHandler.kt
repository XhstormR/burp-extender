package burp

import burp.model.Payload
import burp.model.PayloadPart
import burp.model.PayloadType
import burp.model.insertionPointType
import burp.spel.HttpContextEvaluator

object PayloadHandler {

    fun handle(
        payload: Payload?,
        insertionPoint: IScannerInsertionPoint,
        evaluator: HttpContextEvaluator,
        headers: Map<String, String>?,
        helpers: IExtensionHelpers,
    ): List<ByteArray>? {
        payload ?: return null

        val (part, type, name, values) = payload
        val pass = checkPart(part, insertionPoint) && checkName(name, insertionPoint)
        if (!pass) return null

        val payloads = values
            .mapNotNull { evaluator.evaluate(it) }
            .map {
                when (type) {
                    PayloadType.Append -> insertionPoint.baseValue + it
                    PayloadType.Replace -> it
                }
            }
            .map { it.toByteArray() }
            .map { insertionPoint.buildRequest(it) }

        headers ?: return payloads

        return payloads.map {
            val checkRequestInfo = helpers.analyzeRequest(it)
            val requestBody = it.sliceArray(checkRequestInfo.bodyOffset..it.lastIndex)
            val requestHeaders = checkRequestInfo.headers

            headers
                .mapValues { (_, v) -> evaluator.evaluate(v) }
                .forEach { (k, v) ->
                    requestHeaders.removeIf { it.startsWith("$k:", true) }
                    requestHeaders.add("$k:$v")
                }
            helpers.buildHttpMessage(requestHeaders, requestBody)
        }
    }

    private fun checkPart(part: PayloadPart, insertionPoint: IScannerInsertionPoint) = when (part) {
        PayloadPart.Any -> true
        PayloadPart.Path -> insertionPoint.insertionPointName == PathInsertionPointProvider.INSERTION_POINT_NAME
        else -> insertionPoint.insertionPointType == part.insertionPointType
    }

    private fun checkName(name: String, insertionPoint: IScannerInsertionPoint) = when (name) {
        "*" -> true
        else -> name == insertionPoint.insertionPointName
    }
}
