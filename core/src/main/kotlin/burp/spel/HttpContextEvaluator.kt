package burp.spel

import burp.clazz
import org.springframework.expression.ParserContext
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.expression.spel.support.StandardEvaluationContext

class HttpContextEvaluator(
    val httpContext: HttpContext
) {

    private val parser = SpelExpressionParser()

    private val context = StandardEvaluationContext(httpContext).apply {
        addMethodResolver(HttpContextMethodResolver())
        addPropertyAccessor(HttpContextPropertyAccessor())
    }

    fun evaluate(expression: String) =
        evaluate<String>(expression)

    inline fun <reified T> evaluate(expression: String) =
        doEvaluate(expression, clazz<T>())

    fun <T> doEvaluate(expression: String, clazz: Class<T>) =
        parser.parseExpression(expression, ParserContext.TEMPLATE_EXPRESSION)
            .getValue(context, clazz)

    fun setVariable(key: String, value: String) {
        httpContext.variables[key] = evaluate(value)
    }

    fun setVariable(variables: Map<String, String>) =
        variables.forEach { (k, v) -> setVariable(k, v) }
}
