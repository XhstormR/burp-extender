package burp.spel

import org.springframework.expression.EvaluationContext
import org.springframework.expression.PropertyAccessor
import org.springframework.expression.TypedValue

class HttpContextPropertyAccessor : PropertyAccessor {

    override fun getSpecificTargetClasses() = null

    override fun canRead(context: EvaluationContext, target: Any?, name: String): Boolean {
        target ?: return false
        val httpContext = context.rootObject.value as? HttpContext ?: return false
        // when (name) {
        //     "body" -> {
        //         when (target) {
        //             is IRequestInfo -> return true
        //             is IResponseInfo -> return true
        //         }
        //     }
        // }
        return httpContext.variables.containsKey(name)
    }

    override fun read(context: EvaluationContext, target: Any?, name: String): TypedValue {
        target ?: return TypedValue.NULL
        val httpContext = context.rootObject.value as? HttpContext ?: return TypedValue.NULL
        // when (name) {
        //     "body" -> {
        //         when (target) {
        //             is IRequestInfo -> return TypedValue(httpContext.http.requestInfoWrapper.content)
        //             is IResponseInfo -> return TypedValue(httpContext.http.responseInfoWrapper.content)
        //         }
        //     }
        // }
        return httpContext.variables[name]?.let { TypedValue(it) } ?: return TypedValue.NULL
    }

    override fun canWrite(context: EvaluationContext, target: Any?, name: String) = false

    override fun write(context: EvaluationContext, target: Any?, name: String, newValue: Any?) {
    }
}
