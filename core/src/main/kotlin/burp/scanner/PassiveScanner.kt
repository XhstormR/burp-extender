package burp.scanner

import burp.HttpRequestResponseWrapper
import burp.IBurpExtenderCallbacks
import burp.IHttpRequestResponse
import burp.IScanIssue
import burp.model.ConditionType
import burp.model.Matcher
import burp.model.MatcherPart
import burp.model.MatcherType
import burp.model.Profile
import burp.model.ScanIssue
import burp.model.evaluate
import burp.spel.HttpContext
import burp.spel.HttpContextEvaluator
import burp.toMarkedRequestResponse
import java.io.ByteArrayOutputStream
import java.io.PrintWriter

open class PassiveScanner(
    protected val profile: Profile,
    protected val burpExtender: IBurpExtenderCallbacks,
) {
    protected val helpers = burpExtender.helpers

    open fun scan(
        baseRequestResponse: IHttpRequestResponse,
    ): IScanIssue? {

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

        return if (pass) {
            ScanIssue(
                request.url,
                name,
                detail.description,
                detail.severity,
                detail.confidence,
                http.httpService,
                arrayOf(http.toMarkedRequestResponse(burpExtender)),
            )
        } else null
    }

    protected fun match(
        http: HttpRequestResponseWrapper,
        matchers: List<Matcher>,
        matchersCondition: ConditionType,
        evaluator: HttpContextEvaluator,
    ) = matchersCondition.evaluate(matchers) { (part, type, values, condition, negative, caseSensitive) ->
        val request = http.requestInfoWrapper
        val response = http.responseInfoWrapper
        values.mapNotNull { evaluator.evaluate(it) }.let {
            condition.evaluate(it) { value ->
                val ret = when (type) {
                    MatcherType.Word -> {
                        when (part) {
                            MatcherPart.Url -> request.url.toString().contains(value, caseSensitive)
                            MatcherPart.Method -> request.method.contains(value, caseSensitive)
                            MatcherPart.Request -> request.mark(value, caseSensitive)
                            MatcherPart.RequestBody -> request.markBody(value, caseSensitive)
                            MatcherPart.RequestHeader -> request.markHeader(value, caseSensitive)
                            MatcherPart.Status -> response.statusCode == value.toShort()
                            MatcherPart.Response -> response.mark(value, caseSensitive)
                            MatcherPart.ResponseType -> response.responseType.contains(value, caseSensitive)
                            MatcherPart.ResponseBody -> response.markBody(value, caseSensitive)
                            MatcherPart.ResponseHeader -> response.markHeader(value, caseSensitive)
                            MatcherPart.ResponseTime -> response.checkResponseTime(value)
                        }
                    }
                    MatcherType.Regex -> {
                        val regex = if (caseSensitive) value.toRegex() else value.toRegex(RegexOption.IGNORE_CASE)
                        when (part) {
                            MatcherPart.Url -> request.url.toString().contains(regex)
                            MatcherPart.Method -> request.method.contains(regex)
                            MatcherPart.Request -> request.mark(regex)
                            MatcherPart.RequestBody -> request.markBody(regex)
                            MatcherPart.RequestHeader -> request.markHeader(regex)
                            MatcherPart.Status -> response.statusCode.toString().contains(regex)
                            MatcherPart.Response -> response.mark(regex)
                            MatcherPart.ResponseType -> response.responseType.contains(regex)
                            MatcherPart.ResponseBody -> response.markBody(regex)
                            MatcherPart.ResponseHeader -> response.markHeader(regex)
                            MatcherPart.ResponseTime -> response.checkResponseTime(value)
                        }
                    }
                    MatcherType.Dsl -> TODO()
                }
                if (negative) ret.not() else ret
            }
        }
    }
}
