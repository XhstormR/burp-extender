package io.github.xhstormr.burp.core.spel

import org.springframework.expression.EvaluationContext
import org.springframework.expression.MethodExecutor
import org.springframework.expression.TypedValue
import java.lang.reflect.Method

class RootObjectMethodExecutor(private val method: Method) : MethodExecutor {

    override fun execute(context: EvaluationContext, target: Any, vararg arguments: Any?): TypedValue {
        val rootObject = context.rootObject.value as? RootObject ?: return TypedValue.NULL
        return TypedValue(method.invoke(rootObject, target, *arguments))
    }
}
