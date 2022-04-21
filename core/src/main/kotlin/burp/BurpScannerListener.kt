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

class BurpScannerListener(
    burpExtender: IBurpExtenderCallbacks,
) : IScannerListener,
    IExtensionStateListener {

    private val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
    }

    init {
        burpExtender.registerExtensionStateListener(this)
    }

    override fun newScanIssue(issue: IScanIssue) {
        with(issue) {
            Utilities.out("[+] Found [$severity] issue [$issueName] from [$url]")
        }

        runBlocking {
            val response = httpClient.post("https://httpbin.org/post") {
                contentType(ContentType.Application.Json)
                setBody(mapOf(123 to listOf("aaa", "Jet", "Brains")))
            }
            println(response)
            println(response.bodyAsText())
        }
    }

    override fun extensionUnloaded() = httpClient.close()
}
