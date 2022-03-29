package burp.model

import burp.IHttpRequestResponse
import burp.IHttpService
import burp.IScanIssue
import java.net.URL

data class ScanIssue(
    private val url: URL,
    private val issueName: String,
    private val issueDetail: String,
    private val issueBackground: String,
    private val severity: Severity,
    private val confidence: Confidence,
    private val httpService: IHttpService,
    private val httpMessages: Array<IHttpRequestResponse>,
    private val issueType: Int = 0x08000000,
    private val remediationDetail: String? = null,
    private val remediationBackground: String? = null,
) : IScanIssue {

    override fun getUrl() = url
    override fun getIssueType() = issueType
    override fun getIssueName() = issueName
    override fun getIssueDetail() = issueDetail
    override fun getIssueBackground() = issueBackground
    override fun getRemediationDetail() = remediationDetail
    override fun getRemediationBackground() = remediationBackground
    override fun getSeverity() = severity.toString()
    override fun getConfidence() = confidence.toString()
    override fun getHttpService() = httpService
    override fun getHttpMessages() = httpMessages
}
