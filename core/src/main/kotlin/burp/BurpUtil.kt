package burp

import burp.model.ContentType
import burp.model.code
import java.awt.Frame

object BurpUtil {
    lateinit var callbacks: IBurpExtenderCallbacks
    lateinit var helpers: IExtensionHelpers
    lateinit var settings: ConfigurableSettings

    fun init(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers
        settings = ConfigurableSettings()
    }

    fun log(any: Any?) = callbacks.printOutput(any.toString())

    fun logError(any: Any?) = callbacks.printError(any.toString())

    fun logDebug(any: Any?) {
        if (settings.getBoolean(ConfigurableSettings.LOG_DEBUG_ENABLE_KEY)) log(any)
    }

    fun loadExtensionSetting(key: String) = callbacks.loadExtensionSetting(key)

    fun saveExtensionSetting(key: String, value: String?) = callbacks.saveExtensionSetting(key, value)

    fun getBurpFrame() = Frame.getFrames()
        .firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }

    fun addOrReplaceHeader(request: ByteArray, header: String, value: String?): ByteArray {
        val requestInfo = helpers.analyzeRequest(request)
        val requestBody = request.sliceArray(requestInfo.bodyOffset..request.lastIndex)
        val requestHeaders = requestInfo.headers.apply {
            removeIf { it.startsWith("$header: ", true) }
            value?.let { add("$header: $it") }
        }
        return helpers.buildHttpMessage(requestHeaders, requestBody)
    }

    fun fixContentLength(request: ByteArray): ByteArray {
        val contentLength = "Content-Length: "
        if (helpers.indexOfL(request, contentLength.toByteArray()) == -1) return request

        val requestInfo = helpers.analyzeRequest(request)
        val requestBody = request.sliceArray(requestInfo.bodyOffset..request.lastIndex)
        val requestHeaders = requestInfo.headers
        return helpers.buildHttpMessage(requestHeaders, requestBody)
    }
}

fun IHttpRequestResponse.requestBody(bodyOffset: Int) = request.sliceArray(bodyOffset..request.lastIndex)
fun IHttpRequestResponse.responseBody(bodyOffset: Int) = response.sliceArray(bodyOffset..response.lastIndex)

fun IHttpRequestResponse.requestBodyString(bodyOffset: Int) = request.decodeToString(bodyOffset)
fun IHttpRequestResponse.responseBodyString(bodyOffset: Int) = response.decodeToString(bodyOffset)

fun IHttpRequestResponse.requestHeader(bodyOffset: Int) = request.sliceArray(0..bodyOffset)
fun IHttpRequestResponse.responseHeader(bodyOffset: Int) = response.sliceArray(0..bodyOffset)

fun IHttpRequestResponse.requestHeaderString(bodyOffset: Int) = request.decodeToString(0, bodyOffset)
fun IHttpRequestResponse.responseHeaderString(bodyOffset: Int) = response.decodeToString(0, bodyOffset)

fun IExtensionHelpers.indexOfL(data: ByteArray, pattern: ByteArray, caseSensitive: Boolean = false, from: Int = 0, to: Int = pattern.size) =
    indexOf(data, pattern, caseSensitive, from, to)

fun IExtensionHelpers.indexOfR(data: ByteArray, pattern: ByteArray, caseSensitive: Boolean = false, from: Int = 0, to: Int = pattern.size) =
    indexOf(data, pattern, caseSensitive, from, to).let { if (it == -1) it else it + pattern.size }

fun IRequestInfo.getContentTypeName() = ContentType.values().first { it.code == contentType }.name
