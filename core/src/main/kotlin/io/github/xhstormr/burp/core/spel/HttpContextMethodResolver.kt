package io.github.xhstormr.burp.core.spel

import io.github.xhstormr.burp.core.HttpRequestResponseWrapper
import io.github.xhstormr.burp.core.clazz
import org.springframework.core.convert.TypeDescriptor
import org.springframework.expression.EvaluationContext
import org.springframework.expression.MethodExecutor
import org.springframework.expression.MethodResolver
import org.springframework.util.ReflectionUtils

class HttpContextMethodResolver : MethodResolver {

    companion object {
        private val METHOD_ABC =
            ReflectionUtils.findMethod(clazz<HttpContext>(), "abc", clazz<HttpRequestResponseWrapper.ResponseInfoWrapper>())!!
    }

    override fun resolve(
        context: EvaluationContext,
        target: Any,
        name: String,
        argumentTypes: MutableList<TypeDescriptor>
    ): MethodExecutor? {
        val httpContext = context.rootObject.value as? HttpContext ?: return null
        when (name) {
            "abc" -> {
                when (target) {
                    is HttpRequestResponseWrapper.ResponseInfoWrapper -> return HttpContextMethodExecutor(METHOD_ABC)
                }
            }
        }
        return null
    }
}
