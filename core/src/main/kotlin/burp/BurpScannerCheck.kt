package burp

import burp.model.ConditionType
import burp.model.Matcher
import burp.model.MatcherPart
import burp.model.MatcherType
import burp.model.Profile
import burp.model.ProfileDetail
import burp.model.ProfileType
import burp.model.ScanIssue
import burp.model.evaluate
import burp.spel.HttpContext
import burp.spel.HttpContextEvaluator
import java.io.ByteArrayOutputStream
import java.io.PrintWriter

class BurpScannerCheck(
    val profile: Profile,
    private val burpExtender: IBurpExtenderCallbacks,
    private val burpCollaborator: BurpCollaborator,
) : IScannerCheck {

    private val helpers = burpExtender.helpers

    override fun doPassiveScan(
        baseRequestResponse: IHttpRequestResponse,
    ): List<IScanIssue> {
        val issues = mutableListOf<IScanIssue>()

        if (profile.type != ProfileType.Passive) return issues

        val http = HttpRequestResponseWrapper(baseRequestResponse, helpers)
        val request = http.requestInfoWrapper
        val response = http.responseInfoWrapper
        val httpContext = HttpContext(http, helpers)
        val evaluator = HttpContextEvaluator(httpContext)

        ByteArrayOutputStream().use {
            PrintWriter(it).use {
                with(it) {
                    println("==========")
                    println("doPassiveScan")
                    println("request.size: " + http.request.size)
                    println("response.size: " + http.response.size)
                    println("request.contentType: " + request.contentType)
                    println("request.url: " + request.url)
                    println("request.headers: " + request.headers)
                    println("request.method: " + request.method)
                    println("request.parameters: " + request.parameters)
                    println("response.statusCode: " + response.statusCode)
                    println("response.headers: " + response.headers)
                    println("response.cookies: " + response.cookies)
                    println("response.type: " + response.responseType)
                }
            }
            println(it.toString())
        }

        val (name, _, _, detail, variables, rules, rulesCondition) = profile

        variables?.let { evaluator.setVariable(it.toSortedMap()) }
        println(httpContext.variables)

        val pass = rulesCondition.evaluate(rules) { (_, _, matchers, matchersCondition) ->
            match(http, matchers, matchersCondition, evaluator)
        }

        if (pass) issues.add(toScanIssue(name, detail, http))

        return issues
    }

    override fun doActiveScan(
        baseRequestResponse: IHttpRequestResponse,
        insertionPoint: IScannerInsertionPoint,
    ): List<IScanIssue> {
        val issues = mutableListOf<IScanIssue>()

        if (profile.type != ProfileType.Active) return issues

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
            if (!preMatch(http, matchers, matchersCondition, evaluator)) return@evaluate false

            val checkRequests = PayloadHandler.handle(payload, insertionPoint, evaluator, headers, burpCollaborator)
                ?: return@evaluate false

            ConditionType.Or.evaluate(checkRequests) { checkRequest ->
                val (checkRequestResponse, responseTime) = measureTimeMillisWithResult {
                    burpExtender.makeHttpRequest(baseRequestResponse.httpService, checkRequest.bytes)
                }

                http = HttpRequestResponseWrapper(checkRequestResponse, helpers)
                    .apply { requestInfoWrapper.markers.add(checkRequest.payloadOffset) }
                    .apply { requestInfoWrapper.markers.addAll(http.requestInfoWrapper.markers) }
                    .apply { responseInfoWrapper.responseTime = responseTime }

                checkRequest.oobId?.let { oobId -> burpCollaborator.registerOutOfBandData(oobId, toScanIssue(name, detail, http)) }
                postMatch(http, matchers, matchersCondition, evaluator)
            }
        }

        if (pass) issues.add(toScanIssue(name, detail, http))

        return issues
    }

    private fun preMatch(
        http: HttpRequestResponseWrapper,
        matchers: List<Matcher>,
        matchersCondition: ConditionType,
        evaluator: HttpContextEvaluator,
    ) = matchers.filter { it.part.isRequest }.let { match(http, it, matchersCondition, evaluator) || it.isEmpty() }

    private fun postMatch(
        http: HttpRequestResponseWrapper,
        matchers: List<Matcher>,
        matchersCondition: ConditionType,
        evaluator: HttpContextEvaluator,
    ) = matchers.filterNot { it.part.isRequest }.let { match(http, it, matchersCondition, evaluator) }

    private fun match(
        http: HttpRequestResponseWrapper,
        matchers: List<Matcher>,
        matchersCondition: ConditionType,
        evaluator: HttpContextEvaluator,
    ) = matchersCondition.evaluate(matchers) { (part, type, values, negative, caseSensitive, condition) ->
        val request = http.requestInfoWrapper
        val response = http.responseInfoWrapper
        values.mapNotNull { evaluator.evaluate(it) }.let {
            condition.evaluate(it) { value ->
                val ret = when (type) {
                    MatcherType.Word -> {
                        when (part) {
                            MatcherPart.Url -> request.url.toString().contains(value, caseSensitive)
                            MatcherPart.Host -> request.url.host.contains(value, caseSensitive)
                            MatcherPart.Path -> request.url.path.contains(value, caseSensitive)
                            MatcherPart.Query -> request.url.query.contains(value, caseSensitive)
                            MatcherPart.Method -> request.method.contains(value, caseSensitive)
                            MatcherPart.ContentType -> request.getContentName().contains(value, caseSensitive)
                            MatcherPart.Request -> request.mark(value, caseSensitive)
                            MatcherPart.RequestBody -> request.markBody(value, caseSensitive)
                            MatcherPart.RequestHeader -> request.markHeader(value, caseSensitive)
                            MatcherPart.Status -> response.statusCode.toString() == value
                            MatcherPart.ResponseTime -> response.checkResponseTime(value)
                            MatcherPart.ResponseType -> response.responseType.contains(value, caseSensitive)
                            MatcherPart.Response -> response.mark(value, caseSensitive)
                            MatcherPart.ResponseBody -> response.markBody(value, caseSensitive)
                            MatcherPart.ResponseHeader -> response.markHeader(value, caseSensitive)
                        }
                    }
                    MatcherType.Regex -> {
                        val regex = if (caseSensitive) value.toRegex() else value.toRegex(RegexOption.IGNORE_CASE)
                        when (part) {
                            MatcherPart.Url -> request.url.toString().contains(regex)
                            MatcherPart.Host -> request.url.host.contains(regex)
                            MatcherPart.Path -> request.url.path.contains(regex)
                            MatcherPart.Query -> request.url.query.contains(regex)
                            MatcherPart.Method -> request.method.contains(regex)
                            MatcherPart.ContentType -> request.getContentName().contains(regex)
                            MatcherPart.Request -> request.mark(regex)
                            MatcherPart.RequestBody -> request.markBody(regex)
                            MatcherPart.RequestHeader -> request.markHeader(regex)
                            MatcherPart.Status -> response.statusCode.toString().contains(regex)
                            MatcherPart.ResponseTime -> response.checkResponseTime(value)
                            MatcherPart.ResponseType -> response.responseType.contains(regex)
                            MatcherPart.Response -> response.mark(regex)
                            MatcherPart.ResponseBody -> response.markBody(regex)
                            MatcherPart.ResponseHeader -> response.markHeader(regex)
                        }
                    }
                    MatcherType.Dsl -> TODO()
                }
                if (negative) ret.not() else ret
            }
        }
    }

    private fun toScanIssue(
        name: String,
        detail: ProfileDetail,
        requestResponse: HttpRequestResponseWrapper,
    ): ScanIssue {
        val requestMarkers = requestResponse.requestInfoWrapper.markers.merge()
        val responseMarkers = requestResponse.responseInfoWrapper.markers.merge()
        val requestResponseWithMarkers = burpExtender.applyMarkers(requestResponse, requestMarkers, responseMarkers)

        val requestDetail = requestMarkers
            .takeIf { it.isNotEmpty() }
            ?.map { requestResponse.request.decodeToString(it[0], it[1]) }
            ?.joinToString("", "request detail:<ul>", "</ul>") { "<li>$it</li>" } ?: ""
        val responseDetail = responseMarkers
            .takeIf { it.isNotEmpty() }
            ?.map { requestResponse.response.decodeToString(it[0], it[1]) }
            ?.joinToString("", "response detail:<ul>", "</ul>") { "<li>$it</li>" } ?: ""
        val issueDetail = """
            $requestDetail
            $responseDetail
        """.trimIndent()

        val linkList = detail.links.joinToString("") { "<li>$it</li>" }
        val issueBackground = """
            <p>${detail.description}</p>
            <ul>$linkList</ul>
        """.trimIndent()

        return ScanIssue(
            requestResponse.requestInfoWrapper.url,
            name,
            issueDetail,
            issueBackground,
            detail.severity,
            detail.confidence,
            requestResponse.httpService,
            arrayOf(requestResponseWithMarkers),
        )
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue) =
        if (existingIssue.issueName == newIssue.issueName && existingIssue.issueDetail == newIssue.issueDetail) -1
        else 0
}
