package io.github.xhstormr.burp.core

import burp.IExtensionHelpers
import burp.IHttpRequestResponse
import burp.IScanIssue
import io.github.xhstormr.burp.core.model.MatcherPart
import io.github.xhstormr.burp.core.model.MatcherType
import io.github.xhstormr.burp.core.model.Profile
import io.github.xhstormr.burp.core.model.ScanIssue
import io.github.xhstormr.burp.core.model.evaluate

open class PassiveScanner(
    val profile: Profile,
    val helpers: IExtensionHelpers,
) {

    private fun getMatches(response: ByteArray, match: ByteArray, ignoreCase: Boolean): List<IntArray> {
        val matches = mutableListOf<IntArray>()
        var start = 0
        while (start < response.size) {
            start = helpers.indexOf(response, match, !ignoreCase, start, response.size)
            if (start == -1) break
            matches.add(intArrayOf(start, start + match.size))
            start += match.size
        }
        return matches
    }

    private fun time123(value: String, responseTime: Int): Boolean {
        val (x, y) = value.split('-')
            .take(2)
            .map { it.toInt() }
            .let { it[0] to it[1] }
        return responseTime in x..y
    }

    private fun ByteArray.contains(bytes: ByteArray, ignoreCase: Boolean) =
        getMatches(this, bytes, ignoreCase).isNotEmpty()

    fun scan(
        baseRequestResponse: IHttpRequestResponse,
    ): IScanIssue? {

        val request = helpers.analyzeRequest(baseRequestResponse)
        val response = helpers.analyzeResponse(baseRequestResponse.response)

        println("==========")
        println("doPassiveScan")
        println("request size:" + baseRequestResponse.request.size)
        println("response size:" + baseRequestResponse.response.size)
        println(request.contentType)
        println(request.url)
        println(request.headers)
        println(request.method)
        println(request.parameters)

        println(response.statusCode)
        println(response.headers)
        println(response.cookies)
        println(response.statedMimeType)
        println(response.inferredMimeType)

        val (name, _, _, detail, variables, rules, rulesCondition) = profile
        val responseTime = 0
        val pass = rulesCondition.evaluate(rules) { (matchers, matchersCondition) ->
            matchersCondition.evaluate(matchers) { (part, type, values, condition, negative, ignoreCase) ->
                condition.evaluate(values) { value ->
                    when (type) {
                        MatcherType.Word -> {
                            when (part) {
                                MatcherPart.Url -> request.url.toString().contains(value, ignoreCase)
                                MatcherPart.Method -> request.method.contains(value, ignoreCase)
                                MatcherPart.RequestBody -> baseRequestResponse.requestBody(request.bodyOffset).contains(value.toByteArray(), ignoreCase)
                                MatcherPart.RequestHeader -> baseRequestResponse.requestHeader(request.bodyOffset).contains(value.toByteArray(), ignoreCase)
                                MatcherPart.Status -> response.statusCode == value.toShort()
                                MatcherPart.ResponseBody -> baseRequestResponse.responseBody(response.bodyOffset).contains(value.toByteArray(), ignoreCase)
                                MatcherPart.ResponseHeader -> baseRequestResponse.responseHeader(response.bodyOffset).contains(value.toByteArray(), ignoreCase)
                                MatcherPart.ResponseTime -> time123(value, responseTime)
                            }
                        }
                        MatcherType.Dsl -> TODO()
                        MatcherType.Regex -> TODO()
                    }
                }
            }
        }

        return if (pass) {
            ScanIssue(
                request.url,
                name,
                detail.description,
                detail.severity,
                detail.confidence,
                baseRequestResponse.httpService,
                arrayOf(baseRequestResponse),
            )
        } else null

        // val parserContext = TemplateParserContext()
        // val expressionParser = SpelExpressionParser()
        // val expression = expressionParser.parseExpression(
        //     """isA(123) && md5("hahahaha") && request.method == "GET" && response.statusCode == 200 && response.abc() && response.body.length < 0 """,
        //     parserContext
        // )
        // val context = StandardEvaluationContext(RootObject(baseRequestResponse, helpers)).apply {
        //     addMethodResolver(RootObjectMethodResolver())
        //     addPropertyAccessor(RootObjectPropertyAccessor())
        // }
        //
        // val any = expression.getValue(context, clazz<Boolean>())
        // println(any)

        /**/

        // val matches = getMatches(baseRequestResponse.response, GREP_STRING)
        // return if (matches.isNotEmpty()) {
        //     // report the issue
        //     val issues = ArrayList<IScanIssue>(1)
        //     issues.add(
        //         CustomScanIssue(
        //             baseRequestResponse.httpService,
        //             helpers.analyzeRequest(baseRequestResponse).url,
        //             arrayOf(instance.applyMarkers(baseRequestResponse, null, matches)),
        //             "CMS Info Leakage",
        //             "The response contains the string: " + helpers.bytesToString(GREP_STRING),
        //             "Information"
        //         )
        //     )
        //     issues
        // } else null
    }
}
