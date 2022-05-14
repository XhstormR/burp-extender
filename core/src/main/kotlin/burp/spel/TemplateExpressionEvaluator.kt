package burp.spel

import burp.clazz
import org.springframework.expression.EvaluationContext
import org.springframework.expression.ParserContext
import org.springframework.expression.spel.standard.SpelExpressionParser

object TemplateExpressionEvaluator {

    private val parser = SpelExpressionParser()

    inline fun <reified T> evaluate(context: EvaluationContext, expression: String) =
        doEvaluate(context, expression, clazz<T>())

    fun <T> doEvaluate(context: EvaluationContext, expression: String, clazz: Class<T>) =
        parser.parseExpression(expression, ParserContext.TEMPLATE_EXPRESSION)
            .getValue(context, clazz)
}
