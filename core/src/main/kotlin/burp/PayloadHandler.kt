package burp

import burp.model.Payload
import burp.model.PayloadAction
import burp.model.PayloadPart
import burp.model.insertionPointType
import burp.spel.HttpContextEvaluator

object PayloadHandler {

    fun handle(
        payload: Payload?,
        insertionPoint: IScannerInsertionPoint,
        evaluator: HttpContextEvaluator,
        headers: Map<String, String>?,
        burpCollaborator: BurpCollaborator,
    ): List<ByteArray>? {
        payload ?: return null

        val (part, name, oob, action, values) = payload

        val pass = checkInsertionPoint(insertionPoint, payload)
        if (!pass) return null

        if (oob) {
            with(evaluator.httpContext.http.requestInfoWrapper.url) {
                val host = host.replace('.', '_')
                val path = path.replace('.', '_').replace('/', '_')
                val type = insertionPoint.insertionPointType
                val bc = burpCollaborator.generatePayload()
                evaluator.setVariable("BC", "$host.$path.$type.$bc")
            }
        }

        val payloads = values
            .mapNotNull { evaluator.evaluate(it) }
            .map {
                when (action) {
                    PayloadAction.Append -> insertionPoint.baseValue + it
                    PayloadAction.Prepend -> it + insertionPoint.baseValue
                    PayloadAction.Replace -> it
                }
            }
            .map { it.toByteArray() }
            .map { insertionPoint.buildRequest(it) }

        headers ?: return payloads

        return payloads.map {
            headers
                .mapValues { (_, v) -> evaluator.evaluate(v) }
                .entries
                .fold(it) { acc, (k, v) -> Utilities.addOrReplaceHeader(acc, k, v) }
        }
    }

    private fun checkInsertionPoint(insertionPoint: IScannerInsertionPoint, payload: Payload) =
        checkPart(insertionPoint, payload.part) && checkName(insertionPoint, payload.name)

    private fun checkPart(insertionPoint: IScannerInsertionPoint, part: PayloadPart) = when (part) {
        PayloadPart.Any -> true
        PayloadPart.Path -> insertionPoint.insertionPointName == PathInsertionPointProvider.INSERTION_POINT_NAME
        else -> insertionPoint.insertionPointType == part.insertionPointType
    }

    private fun checkName(insertionPoint: IScannerInsertionPoint, name: String) = when (name) {
        "*" -> true
        else -> insertionPoint.insertionPointName == name
    }
}
