package burp

import burp.insertion.CookieInsertionPointProvider
import burp.insertion.HeaderInsertionPointProvider
import burp.insertion.PathInsertionPointProvider
import burp.insertion.UrlRawInsertionPointProvider
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

open class BurpExtender : IBurpExtender {

    private lateinit var burpExtender: IBurpExtenderCallbacks

    private lateinit var helpers: IExtensionHelpers

    private lateinit var burpPanelHelper: BurpPanelHelper

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        BurpUtil.init(callbacks)
        BurpUtil.log("Loaded $EXTENSION_NAME v$VERSION")

        burpExtender = callbacks
        helpers = callbacks.helpers
        burpPanelHelper = BurpPanelHelper(callbacks)

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerInsertionPointProvider(PathInsertionPointProvider(helpers))
        callbacks.registerScannerInsertionPointProvider(HeaderInsertionPointProvider(helpers))
        callbacks.registerScannerInsertionPointProvider(CookieInsertionPointProvider(helpers))
        callbacks.registerScannerInsertionPointProvider(UrlRawInsertionPointProvider(helpers))
        callbacks.registerScannerListener(BurpScannerListener())
        callbacks.registerExtensionStateListener(createExtensionStateListener())

        SwingUtilities.invokeLater(::initUI)
    }

    private fun initUI() {
        with(createConfigurationTab()) {
            burpExtender.customizeUiComponent(uiComponent)
            burpExtender.addSuiteTab(this)
        }
    }

    private fun createExtensionStateListener() = IExtensionStateListener {
        BurpUtil.log("Extension unloaded successfully")
    }

    private fun createConfigurationTab() = object : ITab {
        override fun getTabCaption() = EXTENSION_NAME
        override fun getUiComponent() = JTabbedPane().apply {
            addTab("Profiles", burpPanelHelper.`$$$getRootComponent$$$`())
        }
    }

    companion object {
        const val EXTENSION_NAME = "Scanner++"
        const val VERSION = "1.0"
    }
}
