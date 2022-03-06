package burp

interface BurpLogger {

    val burpExtender: IBurpExtenderCallbacks

    fun println(any: Any?) = burpExtender.printOutput(any.toString())

    fun printError(any: Any?) = burpExtender.printError(any.toString())
}
