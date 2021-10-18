package io.github.xhstormr.burp.core.spel

import burp.IResponseInfo
import io.github.xhstormr.burp.core.clazz
import org.springframework.core.convert.TypeDescriptor
import org.springframework.expression.EvaluationContext
import org.springframework.expression.MethodExecutor
import org.springframework.expression.MethodResolver
import org.springframework.util.ReflectionUtils

class RootObjectMethodResolver : MethodResolver {

    companion object {
        private val METHOD_ABC =
            ReflectionUtils.findMethod(clazz<RootObject>(), "abc", clazz<IResponseInfo>())!!
    }

    override fun resolve(
        context: EvaluationContext,
        target: Any,
        name: String,
        argumentTypes: MutableList<TypeDescriptor>
    ): MethodExecutor? {
        val rootObject = context.rootObject.value as? RootObject ?: return null
        when (name) {
            "abc" -> {
                when (target) {
                    is IResponseInfo -> return RootObjectMethodExecutor(METHOD_ABC)
                }
            }
        }
        return null
    }
}
