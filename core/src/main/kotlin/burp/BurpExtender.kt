package burp

import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

open class BurpExtender : IBurpExtender, IExtensionStateListener {

    private lateinit var burpExtender: IBurpExtenderCallbacks

    private lateinit var helpers: IExtensionHelpers

    private lateinit var burpPanelHelper: BurpPanelHelper

    private lateinit var burpCollaborator: BurpCollaborator

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        Utilities(callbacks, null, EXTENSION_NAME)
        Utilities.out("Loaded $EXTENSION_NAME v$VERSION")

        burpExtender = callbacks
        helpers = callbacks.helpers
        burpPanelHelper = BurpPanelHelper(callbacks)
        burpCollaborator = BurpCollaborator(callbacks.createBurpCollaboratorClientContext())

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerCheck(BurpScannerCheck(helpers, burpExtender, burpPanelHelper, burpCollaborator))
        callbacks.registerScannerInsertionPointProvider(PathInsertionPointProvider(helpers))
        callbacks.registerScannerListener(createScannerListener())

        SwingUtilities.invokeLater(::initUI)
    }

    override fun extensionUnloaded() {
        burpCollaborator.close()
    }

    private fun initUI() {
        with(createConfigurationTab()) {
            burpExtender.customizeUiComponent(uiComponent)
            burpExtender.addSuiteTab(this)
        }
    }

    private fun createScannerListener() = IScannerListener {
        with(it) {
            Utilities.out("Found [$severity] issue [$issueName] from [$url]")
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
