package burp

class BurpScannerCheck(
    private val helpers: IExtensionHelpers,
    private val burpExtender: IBurpExtenderCallbacks,
    private val burpPanelHelper: BurpPanelHelper,
) : IScannerCheck {

    override fun doPassiveScan(
        baseRequestResponse: IHttpRequestResponse,
    ) = burpPanelHelper.passiveScanners.mapNotNull { it.scan(baseRequestResponse) }

    override fun doActiveScan(
        baseRequestResponse: IHttpRequestResponse,
        insertionPoint: IScannerInsertionPoint,
    ) = burpPanelHelper.activeScanners.mapNotNull { it.scan(baseRequestResponse, insertionPoint) }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue) =
        if (existingIssue.issueName == newIssue.issueName) -1 else 0
}
