package burp

import burp.model.ScanIssue
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class BurpCollaboratorClient(
    private val burpExtender: IBurpExtenderCallbacks,
    base: IBurpCollaboratorClientContext = burpExtender.createBurpCollaboratorClientContext(),
) : IBurpCollaboratorClientContext by base,
    IExtensionStateListener,
    Runnable,
    Closeable {

    init {
        burpExtender.registerExtensionStateListener(this)
    }

    private val executor = Executors.newSingleThreadScheduledExecutor()

    private val future = executor.scheduleAtFixedRate(this, 1, 1, TimeUnit.MINUTES)

    private val issueMap = ConcurrentHashMap<String, ScanIssue>()

    private fun processEvents() {
        val interactions = fetchAllCollaboratorInteractions()
        if (interactions.isEmpty()) return

        Utilities.out("[!] Burp Collaborator received [${interactions.size}] interactions:")
        Utilities.out("---")

        val interactionMap = interactions.map { it.properties }

        interactionMap.forEach {
            it.forEach { (k, v) -> Utilities.out("$k: $v") }
            Utilities.out("---")
        }

        interactionMap
            .mapNotNull { it["interaction_id"] }
            .mapNotNull { issueMap.remove(it) }
            .forEach { burpExtender.addScanIssue(it) }
    }

    fun isRunning() = !future.isDone

    override fun run() = processEvents()

    override fun close() = executor.shutdown()

    override fun extensionUnloaded() = close()

    fun registerOutOfBandData(oobId: String, issue: ScanIssue) {
        issueMap[oobId] = issue
    }
}
