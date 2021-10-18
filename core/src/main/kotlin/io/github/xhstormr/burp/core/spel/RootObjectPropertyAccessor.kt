package io.github.xhstormr.burp.core.spel

import burp.IRequestInfo
import burp.IResponseInfo
import io.github.xhstormr.burp.core.clazz
import org.springframework.expression.EvaluationContext
import org.springframework.expression.PropertyAccessor
import org.springframework.expression.TypedValue

class RootObjectPropertyAccessor : PropertyAccessor {

    override fun getSpecificTargetClasses() = arrayOf(
        clazz<IRequestInfo>(),
        clazz<IResponseInfo>()
    )

    override fun canRead(context: EvaluationContext, target: Any?, name: String): Boolean {
        target ?: return false
        val rootObject = context.rootObject.value as? RootObject ?: return false
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
        target ?: return TypedValue.NULL
        val rootObject = context.rootObject.value as? RootObject ?: return TypedValue.NULL
        when (name) {
            "body" -> {
                when (target) {
                    is IRequestInfo -> return TypedValue(rootObject.requestBody)
                    is IResponseInfo -> return TypedValue(rootObject.responseBody)
                }
            }
        }
        return TypedValue.NULL
    }

    override fun canWrite(context: EvaluationContext, target: Any?, name: String) = false

    override fun write(context: EvaluationContext, target: Any?, name: String, newValue: Any?) {
    }
}
