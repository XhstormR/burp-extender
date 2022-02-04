package io.github.xhstormr.burp.core.scanner

import burp.IBurpExtenderCallbacks
import burp.IHttpRequestResponse
import burp.IScanIssue
import burp.IScannerInsertionPoint
import io.github.xhstormr.burp.core.HttpRequestResponseWrapper
import io.github.xhstormr.burp.core.PayloadHandler
import io.github.xhstormr.burp.core.measureTimeMillisWithResult
import io.github.xhstormr.burp.core.model.ConditionType
import io.github.xhstormr.burp.core.model.Profile
import io.github.xhstormr.burp.core.model.ScanIssue
import io.github.xhstormr.burp.core.model.evaluate
import io.github.xhstormr.burp.core.spel.HttpContext
import io.github.xhstormr.burp.core.spel.HttpContextEvaluator
import io.github.xhstormr.burp.core.toMarkedRequestResponse
import java.io.ByteArrayOutputStream
import java.io.PrintWriter

class ActiveScanner(
    profile: Profile,
    burpExtender: IBurpExtenderCallbacks,
) : PassiveScanner(profile, burpExtender) {

    fun scan(
        baseRequestResponse: IHttpRequestResponse,
        insertionPoint: IScannerInsertionPoint,
    ): IScanIssue? {

        var http = HttpRequestResponseWrapper(baseRequestResponse, helpers)
        val httpContext = HttpContext(http, helpers)
        val evaluator = HttpContextEvaluator(httpContext)

        ByteArrayOutputStream().use {
            PrintWriter(it).use {
                with(it) {
                    println("==========")
                    println("doActiveScan")
                    println("request.url: " + http.requestInfoWrapper.url)
                    println("response.statusCode: " + http.responseInfoWrapper.statusCode)
                    println("insertionPoint: " + insertionPoint)
                    println("insertionPoint.baseValue: " + insertionPoint.baseValue)
                    println("insertionPoint.insertionPointName: " + insertionPoint.insertionPointName)
                    println("insertionPoint.insertionPointType: " + insertionPoint.insertionPointType)
                }
            }
            println(it.toString())
        }

        val (name, _, _, detail, variables, rules, rulesCondition) = profile

        variables?.let { evaluator.setVariable(it.toSortedMap()) }
        println(httpContext.variables)

        val pass = rulesCondition.evaluate(rules) { (payload, headers, matchers, matchersCondition) ->
            val checkRequests = PayloadHandler.handle(payload, insertionPoint, evaluator, headers, helpers) ?: return@evaluate false

            ConditionType.Or.evaluate(checkRequests) { checkRequest ->
                val (checkRequestResponse, time) = measureTimeMillisWithResult {
                    burpExtender.makeHttpRequest(baseRequestResponse.httpService, checkRequest)
                }
                http = HttpRequestResponseWrapper(checkRequestResponse, helpers)
                    .apply { responseInfoWrapper.time = time }
                match(http, matchers, matchersCondition, evaluator)
            }
        }

        return if (pass) {
            ScanIssue(
                http.requestInfoWrapper.url,
                name,
                detail.description,
                detail.severity,
                detail.confidence,
                http.httpService,
                arrayOf(http.toMarkedRequestResponse(burpExtender)),
            )
        } else null
    }
}

/*
INS_PARAM_URL: 0
INS_PARAM_BODY: 1
INS_PARAM_COOKIE: 2
INS_PARAM_XML: 3
INS_PARAM_XML_ATTR: 4
INS_PARAM_MULTIPART_ATTR: 5
INS_PARAM_JSON: 6
INS_PARAM_AMF: 7
INS_HEADER: 32
INS_URL_PATH_FOLDER: 33
INS_URL_PATH_REST: 33
INS_PARAM_NAME_URL: 34
INS_PARAM_NAME_BODY: 35
INS_ENTIRE_BODY: 36
INS_URL_PATH_FILENAME: 37
INS_USER_PROVIDED: 64
INS_EXTENSION_PROVIDED: 65
INS_UNKNOWN: 127
*/
