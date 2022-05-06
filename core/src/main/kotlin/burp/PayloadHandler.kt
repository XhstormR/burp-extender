package burp

import burp.model.Payload
import burp.model.PayloadAction
import burp.model.PayloadPart
import burp.model.code
import burp.spel.HttpContextEvaluator

object PayloadHandler {

    fun handle(
        payload: Payload?,
        insertionPoint: IScannerInsertionPoint,
        evaluator: HttpContextEvaluator,
        headers: Map<String, String>?,
        burpCollaboratorClient: BurpCollaboratorClient,
    ): List<RequestHolder>? {
        payload ?: return null

        val (part, name, oob, action, values) = payload

        val pass = checkPayload(payload, insertionPoint)
        if (!pass) return null

        var oobId: String? = null
        if (oob) {
            with(evaluator.httpContext.http.requestInfoWrapper.url) {
                val host = host.replace('.', '_')
                val path = path.replace('.', '_').replace('/', '_')
                val type = insertionPoint.insertionPointType
                oobId = burpCollaboratorClient.generatePayload(false)
                val oobHost = "$oobId.${burpCollaboratorClient.collaboratorServerLocation}"
                evaluator.setVariable("OOB", "$host.$path.$type.$oobHost")
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
            .map { RequestHolder(insertionPoint.buildRequest(it), insertionPoint.getPayloadOffsets(it), oobId) }

        headers ?: return payloads

        return payloads.map { holder ->
            headers
                .mapValues { (_, v) -> evaluator.evaluate(v) }
                .entries
                .fold(holder.bytes) { acc, (k, v) -> BurpUtil.addOrReplaceHeader(acc, k, v) }
                .let { RequestHolder(it, holder.payloadOffset, oobId) }
        }
    }

    private fun checkPayload(payload: Payload, insertionPoint: IScannerInsertionPoint) =
        when (insertionPoint.insertionPointType) {
            IScannerInsertionPoint.INS_EXTENSION_PROVIDED -> checkCustomizeInsertionPoint(payload, insertionPoint)
            else -> checkPart(payload.part, insertionPoint.insertionPointType) && checkName(payload.name, insertionPoint.insertionPointName)
        }

    private fun checkCustomizeInsertionPoint(payload: Payload, insertionPoint: IScannerInsertionPoint) =
        insertionPoint.insertionPointName.split('|').takeIf { it.size == 2 }?.let {
            val (insertionPointType, insertionPointName) = it
            checkPart(payload.part, insertionPointType.toByte()) && checkName(payload.name, insertionPointName)
        } ?: false

    private fun checkPart(part: PayloadPart, insertionPointType: Byte) = when (part) {
        PayloadPart.Any -> true
        else -> part.code == insertionPointType
    }

    private fun checkName(name: String, insertionPointName: String) = when (name) {
        "*" -> true
        else -> name.toRegex().containsMatchIn(insertionPointName)
    }

    class RequestHolder(val bytes: ByteArray, val payloadOffset: IntArray, val oobId: String?)
}
