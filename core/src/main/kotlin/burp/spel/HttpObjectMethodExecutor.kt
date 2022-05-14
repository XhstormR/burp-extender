package burp.spel

import org.springframework.expression.EvaluationContext
import org.springframework.expression.MethodExecutor
import org.springframework.expression.TypedValue
import java.lang.reflect.Method

class HttpObjectMethodExecutor(private val method: Method) : MethodExecutor {

    override fun execute(context: EvaluationContext, target: Any, vararg arguments: Any?): TypedValue {
        val httpObject = context.rootObject.value as? HttpObject ?: return TypedValue.NULL
        return TypedValue(method.invoke(httpObject, target, *arguments))
    }
}
