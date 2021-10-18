package io.github.xhstormr.burp.core

import com.typesafe.config.ConfigFactory
import io.github.xhstormr.burp.core.model.Profile
import kotlinx.serialization.hocon.Hocon
import kotlinx.serialization.hocon.decodeFromConfig
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Tests {

    @BeforeAll
    fun beforeAll() {
        println("BeforeAll")
    }

    @Test
    fun test1() {
        val profile = ConfigFactory.load("profile/example.conf")
            .let { Hocon.decodeFromConfig<Profile>(it) }
        println(profile)
    }

    @Test
    fun test2() {
        // val scriptEngine = GraalJSScriptEngine.create()
        // // val bindings = scriptEngine.createBindings()
        // // bindings["obj"] = "example.conf"
        // // scriptEngine.setBindings(bindings, ScriptContext.ENGINE_SCOPE)
        // // println(scriptEngine)
        // // println(scriptEngine.eval("example.conf"))
        // // println(scriptEngine.eval("1+1"))
        // // println(scriptEngine.eval("obj+1"))
        // // println(scriptEngine.eval("obj.length+1"))
        // val bindings = scriptEngine.getBindings(ScriptContext.ENGINE_SCOPE)
        // bindings["polyglot.js.allowHostAccess"] = true
        // bindings["polyglot.js.allowHostClassLookup"] = Predicate<String> { true }
        // bindings["javaObj1"] = Any()
        // val any = scriptEngine.eval("(javaObj1 instanceof Java.type('java.lang.Object'));") as Boolean
        // println(any)
    }

    @Test
    fun test3() {
        // val parser = SpelExpressionParser()
        // val expression = parser.parseExpression("""isA(123) && md5("hahahaha")""")
        // val context = StandardEvaluationContext(RootObject(response))
        // println(expression.getValue(context))
    }
}
