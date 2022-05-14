package burp.spel

import burp.HttpRequestResponseWrapper
import burp.clazz
import org.springframework.core.convert.TypeDescriptor
import org.springframework.expression.EvaluationContext
import org.springframework.expression.MethodExecutor
import org.springframework.expression.MethodResolver
import org.springframework.util.ReflectionUtils

class HttpObjectMethodResolver : MethodResolver {

    companion object {
        private val METHOD_ABC =
            ReflectionUtils.findMethod(clazz<HttpObject>(), "abc", clazz<HttpRequestResponseWrapper.ResponseInfoWrapper>())!!
    }

    override fun resolve(
        context: EvaluationContext,
        target: Any,
        name: String,
        argumentTypes: MutableList<TypeDescriptor>
    ): MethodExecutor? {
        val httpObject = context.rootObject.value as? HttpObject ?: return null
        when (name) {
            "abc" -> {
                when (target) {
                    is HttpRequestResponseWrapper.ResponseInfoWrapper -> return HttpObjectMethodExecutor(METHOD_ABC)
                }
            }
        }
        return null
    }
}
