package burp

import burp.model.ConditionType
import burp.model.Profile
import burp.model.evaluate
import burp.spel.HttpContext
import burp.spel.HttpContextEvaluator
import com.typesafe.config.ConfigFactory
import kotlinx.serialization.hocon.Hocon
import kotlinx.serialization.hocon.decodeFromConfig
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.springframework.expression.spel.standard.SpelExpressionParser

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Tests {

    @BeforeAll
    fun beforeAll() {
        println("BeforeAll")
    }

    @Test
    fun test1() {
        val profile = ConfigFactory.load("profile/passive-example.conf")
            .let { Hocon.decodeFromConfig<Profile>(it) }
        println(profile)
    }

    @Test
    fun test2() {
        val parser = SpelExpressionParser()

        var message = parser.parseExpression(
            "'Hello World'.concat('!')"
        ).value
        println(message)

        message = parser.parseExpression(
            "'Hello World'.concat('!').bytes.length"
        ).value
        println(message)

        message = parser.parseExpression(
            "'5.00' matches '^-?\\d+(\\.\\d{2})?$'"
        ).getValue(Boolean::class.java)
        println(message)

        message = parser.parseExpression(
            "#this.?[ #this < -3].empty"
        ).getValue(listOf(1, 2, 3, 4, 5))
        println(message)
    }

    @Test
    fun test3() {
        val mRequestInfoWrapper = mock<HttpRequestResponseWrapper.RequestInfoWrapper> {
            on { bytes } doReturn byteArrayOf(1, 2, 3, 4, 5)
            on { body } doReturn "test"
        }
        val mResponseInfoWrapper = mock<HttpRequestResponseWrapper.ResponseInfoWrapper> {
            on { bytes } doReturn byteArrayOf(1, 2, 3)
            on { body } doReturn "test"
        }
        val mHttp = mock<HttpRequestResponseWrapper> {
            on { requestInfoWrapper } doReturn mRequestInfoWrapper
            on { responseInfoWrapper } doReturn mResponseInfoWrapper
        }
        val mHelpers = mock<IExtensionHelpers>()
        val httpContextEvaluator = HttpContextEvaluator(HttpContext(mHttp, mHelpers))

        val variables = mapOf(
            "r1" to "#{randomInt(200, 300)}",
            "r2" to "#{randomString(r1)}",
            "r3" to "#{randomDouble(0.0,1.0)}",
        )
        httpContextEvaluator.setVariable(variables)
        println(httpContextEvaluator.httpContext.variables)
        val expressionString =
            """#{('Hello World'+'!').bytes.length} #{r1+'||'+r2} #{isA(123)} #{md5("hahahaha")} request.method == "GET" response.statusCode == 200 #{response.abc()} #{response.body.length}"""
        println(httpContextEvaluator.evaluate(expressionString))
    }

    @Test
    fun test4() {
        val oneTrue = arrayOf(false, true)
        val allTrue = arrayOf(true, true)
        val allFalse = arrayOf(false, false)

        val or = ConditionType.Or
        val and = ConditionType.And

        Assertions.assertTrue(or.evaluate(oneTrue) { it })
        Assertions.assertTrue(or.evaluate(allTrue) { it })
        Assertions.assertFalse(or.evaluate(allFalse) { it })

        Assertions.assertFalse(and.evaluate(oneTrue) { it })
        Assertions.assertTrue(and.evaluate(allTrue) { it })
        Assertions.assertFalse(and.evaluate(allFalse) { it })

        Assertions.assertFalse(or.evaluate(listOf(), ::TODO))
        Assertions.assertTrue(and.evaluate(listOf(), ::TODO))
    }

    @Test
    fun regex1() {
        val input = "1234gUnicorn1234"
        val pattern = """(?i)Gu.*rn"""
        val regex = pattern.toRegex()

        Assertions.assertFalse(regex.matches(input))
        Assertions.assertTrue(regex.containsMatchIn(input))

        Assertions.assertNull(regex.matchEntire(input))
        Assertions.assertNotNull(regex.find(input))

        val result = regex.find(input)!!
        println(result.value)
        println(result.range)
        println(result.groups)
    }

    @Test
    fun regex2() {
        val input = """<a href="/aria2/aria2/releases/download/release-1.36.0/aria2-1.36.0-win-64bit-build1.zip" rel="nofollow">"""
        val pattern = """/release-[\d.]+/aria2-(?<version>[\d.]+)-win-64bit-build(?<build>[\d]+)\.zip"""
        val regex = pattern.toRegex()

        Assertions.assertFalse(regex.matches(input))
        Assertions.assertTrue(regex.containsMatchIn(input))

        Assertions.assertNull(regex.matchEntire(input))
        Assertions.assertNotNull(regex.find(input))

        val matchResult = regex.find(input) ?: return
        matchResult.groups.forEach { println(it) }
        val version = matchResult.groups["version"]?.value
        val build = matchResult.groups["build"]?.value
        println("checkver: $version-$build")
    }

    @Test
    fun test6() {
        val list1 = listOf(
            intArrayOf(1, 3),
            intArrayOf(2, 4),
            intArrayOf(5, 6),
            intArrayOf(7, 9),
            intArrayOf(9, 10),
            intArrayOf(11, 12),
        )
        list1.merge().forEach {
            println(it.contentToString())
        }
    }

    @Test
    fun test7() {
        val callbacks = mock<IBurpExtenderCallbacks>()
        val generalSettings = GeneralSettings.Builder()
            .withErrorConsumer(callbacks::printError)
            .withOutputConsumer(callbacks::printOutput)
            .withExtensionSettingSaver(callbacks::saveExtensionSetting)
            .withExtensionSettingLoader(callbacks::loadExtensionSetting)
            .build()
        println(callbacks)
        println(generalSettings)
    }
}
