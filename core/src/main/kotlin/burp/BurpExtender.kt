package burp

import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

open class BurpExtender : IBurpExtender {

    private lateinit var burpExtender: IBurpExtenderCallbacks

    private lateinit var helpers: IExtensionHelpers

    private lateinit var burpPanelHelper: BurpPanelHelper

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        Utilities(callbacks, null, EXTENSION_NAME)
        Utilities.out("Loaded $EXTENSION_NAME v$VERSION")

        burpExtender = callbacks
        helpers = callbacks.helpers
        burpPanelHelper = BurpPanelHelper(callbacks)

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerInsertionPointProvider(PathInsertionPointProvider(helpers))
        callbacks.registerScannerInsertionPointProvider(HeaderInsertionPointProvider(helpers))
        callbacks.registerScannerListener(createScannerListener())

        SwingUtilities.invokeLater(::initUI)
    }

    private fun initUI() {
        with(createConfigurationTab()) {
            burpExtender.customizeUiComponent(uiComponent)
            burpExtender.addSuiteTab(this)
        }
    }

    private fun createScannerListener() = IScannerListener {
        with(it) {
            Utilities.out("[+] Found [$severity] issue [$issueName] from [$url]")
        }
    }

    private fun createConfigurationTab() = object : ITab {
        override fun getTabCaption() = EXTENSION_NAME
        override fun getUiComponent() = JTabbedPane().apply {
            addTab("Profiles", burpPanelHelper.`$$$getRootComponent$$$`())
        }
    }

    companion object {
        private const val EXTENSION_NAME = "Burp Extender"
        private const val VERSION = "1.0"
    }
}
