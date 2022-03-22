package burp

class GeneralSettings(builder: Builder) {

    private val errorConsumer: ((String) -> Unit)
    private val outputConsumer: ((String) -> Unit)
    private val extensionSettingSaver: ((String, String?) -> Unit)
    private val extensionSettingLoader: ((String) -> String?)

    init {
        errorConsumer = builder.errorConsumer ?: System.err::println
        outputConsumer = builder.outputConsumer ?: ::println
        extensionSettingSaver = builder.extensionSettingSaver ?: { _, _ -> errorConsumer("saver wasn't configured") }
        extensionSettingLoader = builder.extensionSettingLoader ?: { null }
    }

    fun log(any: Any?) = outputConsumer(any.toString())

    fun logError(any: Any?) = errorConsumer(any.toString())

    fun loadExtensionSetting(key: String) = extensionSettingLoader(key)

    fun saveExtensionSetting(key: String, value: String?) = extensionSettingSaver(key, value)

    class Builder {
        var errorConsumer: ((String) -> Unit)? = null
        var outputConsumer: ((String) -> Unit)? = null
        var extensionSettingSaver: ((String, String?) -> Unit)? = null
        var extensionSettingLoader: ((String) -> String?)? = null

        fun withErrorConsumer(errorConsumer: (String) -> Unit) =
            also { it.errorConsumer = errorConsumer }

        fun withOutputConsumer(outputConsumer: (String) -> Unit) =
            also { it.outputConsumer = outputConsumer }

        fun withExtensionSettingSaver(extensionSettingSaver: (String, String?) -> Unit) =
            also { it.extensionSettingSaver = extensionSettingSaver }

        fun withExtensionSettingLoader(extensionSettingLoader: (String) -> String?) =
            also { it.extensionSettingLoader = extensionSettingLoader }

        fun build() = GeneralSettings(this)
    }
}
