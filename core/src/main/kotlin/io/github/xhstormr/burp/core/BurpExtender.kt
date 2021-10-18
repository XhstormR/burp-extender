package io.github.xhstormr.burp.core

import burp.IBurpExtender
import burp.IBurpExtenderCallbacks
import burp.IExtensionHelpers
import burp.IHttpRequestResponse
import burp.IScanIssue
import burp.IScannerCheck
import burp.IScannerInsertionPoint
import burp.IScannerListener
import burp.ITab
import io.github.xhstormr.burp.core.model.ScanIssue
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.expression.spel.support.StandardEvaluationContext
import javax.swing.SwingUtilities

open class BurpExtender :
    IBurpExtender,
    ITab,
    IScannerCheck,
    IScannerListener {

    private lateinit var instance: IBurpExtenderCallbacks

    private lateinit var helpers: IExtensionHelpers

    private lateinit var burpPanelHelper: BurpPanelHelper

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        instance = callbacks
        helpers = callbacks.helpers
        burpPanelHelper = BurpPanelHelper(callbacks)

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerCheck(this)
        callbacks.registerScannerListener(this)

        SwingUtilities.invokeLater(::initUI)
    }

    // fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
    //     // instance.sendToSpider(URL("https://www.qq.com/"))
    //     println("=========")
    //     println("processHttpMessage")
    //     println(toolFlag)
    //     println(messageIsRequest)
    //     messageInfo.comment = "123"
    //     println(messageInfo.comment)
    //     println(messageInfo.httpService.protocol)
    //     println(messageInfo.httpService.host)
    //     println(messageInfo.httpService.port)
    //     if (messageIsRequest) {
    //         val request = helpers.analyzeRequest(messageInfo)
    //         println("request.url: " + request.url)
    //         println("request.headers.size: " + request.headers.size)
    //         println("request.method: " + request.method)
    //         println("request.bodyOffset: " + request.bodyOffset)
    //         println("body: " + messageInfo.requestBody(request.bodyOffset))
    //
    //         println("messageInfo.request.size: " + messageInfo.request.size)
    //         println("messageInfo.response: " + messageInfo.response)
    //     } else {
    //         val response = helpers.analyzeResponse(messageInfo.response)
    //         println("response.statusCode: " + response.statusCode)
    //         println("response.inferredMimeType: " + response.inferredMimeType)
    //         println("response.statedMimeType: " + response.statedMimeType)
    //         println("response.bodyOffset: " + response.bodyOffset)
    //         println("messageInfo.request.size: " + messageInfo.request.size)
    //         println("messageInfo.response: " + messageInfo.response)
    //     }
    // }

    override fun doPassiveScan(
        baseRequestResponse: IHttpRequestResponse
    ): List<IScanIssue>? {
        // instance.applyMarkers()

        println("=========")
        println("doPassiveScan")
        val request = helpers.analyzeRequest(baseRequestResponse)
        val response = helpers.analyzeResponse(baseRequestResponse.response)
        println(request.url)
        println(response.statusCode)

        val parser = SpelExpressionParser()
        val expression = parser.parseExpression(
            """isA(123) && md5("hahahaha") && request.method == "GET" && response.statusCode == 200 """
        )
        val context = StandardEvaluationContext(RootObject(request, response))
        println(expression.getValue(context))

        val list = burpPanelHelper.profiles.map {
            ScanIssue(
                request.url,
                1,
                it.name,
                it.detail.description,
                null,
                null,
                null,
                it.detail.severity,
                it.detail.confidence,
                baseRequestResponse.httpService,
                arrayOf(baseRequestResponse),
            )
        }
        return list
    }

    override fun doActiveScan(
        baseRequestResponse: IHttpRequestResponse,
        insertionPoint: IScannerInsertionPoint
    ): List<IScanIssue>? {
        println("=========")
        println("doActiveScan")
        val request = helpers.analyzeRequest(baseRequestResponse)
        val response = helpers.analyzeResponse(baseRequestResponse.response)
        println(request.url)
        println(response.statusCode)
        println(insertionPoint)
        println(insertionPoint.insertionPointName)
        println(insertionPoint.insertionPointType)
        return null
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue) =
        if (existingIssue.issueName == newIssue.issueName) -1 else 0

    override fun newScanIssue(issue: IScanIssue) = println("${issue.url} || ${issue.issueName}")

    private fun println(any: Any?) = instance.printOutput(any.toString())

    private fun printError(any: Any?) = instance.printError(any.toString())

    override fun getTabCaption() = EXTENSION_NAME

    override fun getUiComponent() = burpPanelHelper.`$$$getRootComponent$$$`()

    private fun initUI() {
        instance.customizeUiComponent(burpPanelHelper.`$$$getRootComponent$$$`())
        instance.addSuiteTab(this)
    }

    companion object {
        private const val EXTENSION_NAME = "Burp Extender"
    }
}
