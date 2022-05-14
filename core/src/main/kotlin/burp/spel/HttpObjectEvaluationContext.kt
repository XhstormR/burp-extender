package burp.spel

import burp.evaluate
import org.springframework.expression.spel.support.StandardEvaluationContext

class HttpObjectEvaluationContext(
    val httpObject: HttpObject,
) : StandardEvaluationContext(httpObject) {

    init {
        addMethodResolver(HttpObjectMethodResolver())
        addPropertyAccessor(HttpObjectPropertyAccessor())
    }

    override fun setVariable(name: String, value: Any?) =
        super.setVariable(name, evaluate(value.toString()))
}
