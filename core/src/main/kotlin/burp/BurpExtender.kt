package burp

import burp.insertion.CookieInsertionPointProvider
import burp.insertion.HeaderInsertionPointProvider
import burp.insertion.PathInsertionPointProvider
import burp.insertion.UrlRawInsertionPointProvider
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

open class BurpExtender : IBurpExtender {

    private lateinit var burpPanelHelper: BurpPanelHelper

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        BurpUtil.init(callbacks)
        BurpUtil.log("Loaded $EXTENSION_NAME v$VERSION")

        burpPanelHelper = BurpPanelHelper(callbacks)

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerInsertionPointProvider(PathInsertionPointProvider(callbacks.helpers))
        callbacks.registerScannerInsertionPointProvider(HeaderInsertionPointProvider(callbacks.helpers))
        callbacks.registerScannerInsertionPointProvider(CookieInsertionPointProvider(callbacks.helpers))
        callbacks.registerScannerInsertionPointProvider(UrlRawInsertionPointProvider(callbacks.helpers))
        callbacks.registerScannerListener(BurpScannerListener())
        callbacks.registerExtensionStateListener(createExtensionStateListener())

        SwingUtilities.invokeLater(::initUI)
    }

    private fun initUI() {
        with(createConfigurationTab()) {
            BurpUtil.callbacks.customizeUiComponent(uiComponent)
            BurpUtil.callbacks.addSuiteTab(this)
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
