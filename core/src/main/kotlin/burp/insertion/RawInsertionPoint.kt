package burp.insertion

import burp.BurpUtil
import burp.IScannerInsertionPoint
import java.io.ByteArrayOutputStream

class RawInsertionPoint(
    val name: String,
    req: ByteArray,
    start: Int,
    end: Int,
) : IScannerInsertionPoint {

    private val prefix: ByteArray
    private val suffix: ByteArray
    private val baseValue: String

    init {
        prefix = req.copyOfRange(0, start)
        suffix = req.copyOfRange(end, req.size)
        baseValue = String(req.copyOfRange(start, end))
    }

    override fun getInsertionPointType() = IScannerInsertionPoint.INS_EXTENSION_PROVIDED

    override fun getInsertionPointName() = name

    override fun getBaseValue() = baseValue

    override fun getPayloadOffsets(payload: ByteArray) =
        intArrayOf(prefix.size, prefix.size + payload.size)

    override fun buildRequest(payload: ByteArray): ByteArray {
        val outputStream = ByteArrayOutputStream().apply {
            write(prefix)
            write(payload)
            write(suffix)
        }
        return BurpUtil.fixContentLength(outputStream.toByteArray())
    }
}
