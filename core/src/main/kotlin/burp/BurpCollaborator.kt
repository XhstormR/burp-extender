package burp

import java.io.Closeable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class BurpCollaborator(
    base: IBurpCollaboratorClientContext,
) : IBurpCollaboratorClientContext by base,
    Runnable,
    Closeable {

    private val executor = Executors.newSingleThreadScheduledExecutor()

    private val future = executor.scheduleAtFixedRate(this, 1, 1, TimeUnit.MINUTES)

    private fun processEvents() {
        val interactions = fetchAllCollaboratorInteractions()
        if (interactions.isNotEmpty()) {
            Utilities.out("Burp Collaborator received ${interactions.size} interactions:")
            Utilities.out("---")
            interactions
                .map { it.properties }
                .forEach {
                    it.forEach { (k, v) -> Utilities.out("$k: $v") }
                    Utilities.out("---")
                }
        }
    }

    fun isRunning() = !future.isDone

    override fun run() = processEvents()

    override fun close() = executor.shutdown()
}
