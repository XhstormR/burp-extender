package io.github.xhstormr.burp.core

import burp.IBurpExtender
import burp.IBurpExtenderCallbacks
import burp.IExtensionHelpers
import burp.IScanIssue
import burp.IScannerListener
import burp.ITab
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

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerCheck(BurpScannerCheck(helpers, burpExtender, burpPanelHelper))
        callbacks.registerScannerListener(this)
        callbacks.registerScannerInsertionPointProvider(PathInsertionPointProvider(helpers))

        SwingUtilities.invokeLater(::initUI)
    }

    override fun newScanIssue(issue: IScanIssue) = println("${issue.url} || ${issue.issueName}")

    override fun getTabCaption() = EXTENSION_NAME

    override fun getUiComponent() = burpPanelHelper.`$$$getRootComponent$$$`()

    private fun initUI() {
        burpExtender.customizeUiComponent(uiComponent)
        burpExtender.addSuiteTab(this)
    }

    companion object {
        private const val EXTENSION_NAME = "Burp Extender"
    }
}
