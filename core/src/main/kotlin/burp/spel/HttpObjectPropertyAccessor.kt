package burp.spel

import burp.IRequestInfo
import burp.IResponseInfo
import org.springframework.expression.EvaluationContext
import org.springframework.expression.PropertyAccessor
import org.springframework.expression.TypedValue

class HttpObjectPropertyAccessor : PropertyAccessor {

    override fun getSpecificTargetClasses() = null

    override fun canRead(context: EvaluationContext, target: Any?, name: String): Boolean {
        val httpObject = context.rootObject.value as? HttpObject ?: return false
        when (name) {
            "body" -> {
                when (target) {
                    is IRequestInfo -> return true
                    is IResponseInfo -> return true
                }
            }
        }
        return false
    }

    override fun read(context: EvaluationContext, target: Any?, name: String): TypedValue {
        val httpObject = context.rootObject.value as? HttpObject ?: return TypedValue.NULL
        when (name) {
            "body" -> {
                when (target) {
                    is IRequestInfo -> return TypedValue(httpObject.http.requestInfoWrapper.body)
                    is IResponseInfo -> return TypedValue(httpObject.http.responseInfoWrapper.body)
                }
            }
        }
        return TypedValue.NULL
    }

    override fun canWrite(context: EvaluationContext, target: Any?, name: String) = false

    override fun write(context: EvaluationContext, target: Any?, name: String, newValue: Any?) {
    }
}
