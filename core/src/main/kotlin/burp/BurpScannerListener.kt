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

    private var issueCallbackEnable = BurpUtil.settings.getBoolean(ConfigurableSettings.ISSUE_REPORT_ENABLE_KEY)

    init {
        BurpUtil.callbacks.registerExtensionStateListener(this)
        BurpUtil.settings.register(ConfigurableSettings.ISSUE_REPORT_ENABLE_KEY) {
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
            val callbackUrl = BurpUtil.settings.getString(ConfigurableSettings.ISSUE_REPORT_URL_KEY)
            val response = httpClient.post(callbackUrl) {
                contentType(ContentType.Application.Json)
                setBody(
                    mapOf(
                        "url" to issue.url.toString(),
                        "issueName" to issue.issueName,
                        "issueDetail" to issue.issueDetail,
                        "issueBackground" to issue.issueBackground,
                        "severity" to issue.severity,
                        "confidence" to issue.confidence,
                        "jiraId" to issue.httpMessages.firstOrNull()?.let(::findJiraId),
                    )
                )
            }
            BurpUtil.logDebug(response)
            BurpUtil.logDebug(response.bodyAsText())
        }
    }

    private fun findJiraId(requestResponse: IHttpRequestResponse): String? {
        val prefix = "jira_id: "
        val requestInfo = BurpUtil.helpers.analyzeRequest(requestResponse.request)
        return requestInfo.headers.find { it.startsWith(prefix, true) }
            ?.substring(prefix.length)
    }

    override fun extensionUnloaded() = httpClient.close()
}
