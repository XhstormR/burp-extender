package burp.spel

import org.springframework.expression.EvaluationContext
import org.springframework.expression.MethodExecutor
import org.springframework.expression.TypedValue
import java.lang.reflect.Method

class HttpContextMethodExecutor(private val method: Method) : MethodExecutor {

    override fun execute(context: EvaluationContext, target: Any, vararg arguments: Any?): TypedValue {
        val httpContext = context.rootObject.value as? HttpContext ?: return TypedValue.NULL
        return TypedValue(method.invoke(httpContext, target, *arguments))
    }
}
