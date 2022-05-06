package burp

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking

class BurpScannerListener :
    IScannerListener,
    IExtensionStateListener {

    private val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
    }

    private var issueCallbackEnable = BurpUtil.settings.getBoolean(ConfigurableSettings.ISSUE_CALLBACK_ENABLE_KEY)

    init {
        BurpUtil.callbacks.registerExtensionStateListener(this)
        BurpUtil.settings.register(ConfigurableSettings.ISSUE_CALLBACK_ENABLE_KEY) {
            issueCallbackEnable = it.toBoolean()
        }
        HttpClient(CIO).close() // fully load class to avoid ClassNotFoundException when calling extensionUnloaded method
    }

    override fun newScanIssue(issue: IScanIssue) {
        with(issue) {
            BurpUtil.log("[+] Found [$severity] issue [$issueName] from [$url]")
        }
        if (issueCallbackEnable) postScanIssue(issue)
    }

    private fun postScanIssue(issue: IScanIssue) {
        runBlocking {
            val jiraId = findJiraId(issue.httpMessages.first())
            val callbackUrl = BurpUtil.settings.getString(ConfigurableSettings.ISSUE_CALLBACK_URL_KEY)
            val response = httpClient.post(callbackUrl) {
                contentType(ContentType.Application.Json)
                setBody(mapOf(123 to listOf("aaa", "Jet", "Brains", jiraId)))
            }
            BurpUtil.logDebug(response)
            BurpUtil.logDebug(response.bodyAsText())
        }
    }

    private fun findJiraId(requestResponse: IHttpRequestResponse): String? {
        val requestInfo = BurpUtil.helpers.analyzeRequest(requestResponse.request)
        return requestInfo.headers.find { it.startsWith("jira_id: ", true) }
            ?.substring(9)
    }

    override fun extensionUnloaded() = httpClient.close()
}
