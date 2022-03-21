package burp

import javax.swing.SwingUtilities

open class BurpExtender :
    IBurpExtender,
    ITab,
    IScannerListener,
    BurpLogger {

    override lateinit var burpExtender: IBurpExtenderCallbacks

    private lateinit var helpers: IExtensionHelpers

    private lateinit var burpPanelHelper: BurpPanelHelper

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        burpExtender = callbacks
        helpers = callbacks.helpers
        burpPanelHelper = BurpPanelHelper(callbacks)

        Utilities(callbacks, null, EXTENSION_NAME)

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerCheck(BurpScannerCheck(helpers, burpExtender, burpPanelHelper))
        callbacks.registerScannerListener(this)
        callbacks.registerScannerInsertionPointProvider(PathInsertionPointProvider(helpers))

        println("Loaded $EXTENSION_NAME v$VERSION")
        SwingUtilities.invokeLater(::initUI)
    }

    override fun newScanIssue(issue: IScanIssue) = with(issue) {
        println("Found [$severity] issue [$issueName] from [$url]")
    }

    override fun getTabCaption() = EXTENSION_NAME

    override fun getUiComponent() = burpPanelHelper.`$$$getRootComponent$$$`()

    private fun initUI() {
        burpExtender.customizeUiComponent(uiComponent)
        burpExtender.addSuiteTab(this)
    }

    companion object {
        private const val EXTENSION_NAME = "Burp Extender"
        private const val VERSION = "1.0"
    }
}
