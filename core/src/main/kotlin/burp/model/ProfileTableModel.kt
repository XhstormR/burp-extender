package burp.model

import burp.BurpCollaborator
import burp.BurpScannerCheck
import burp.IBurpExtenderCallbacks
import burp.clazz
import javax.swing.table.DefaultTableModel

class ProfileTableModel(
    private val burpExtender: IBurpExtenderCallbacks,
) : DefaultTableModel(PROFILE_COLUMNNAMES, 0) {

    private val burpCollaborator = BurpCollaborator(burpExtender)

    private var scanners = listOf<BurpScannerCheck>()

    init {
        addTableModelListener(TableCellChangedListener(::cellUpdated))
    }

    fun setData(profiles: Collection<Profile>) {
        val columnData = profiles
            .map { it.row() }
            .toTypedArray()
        setDataVector(columnData, PROFILE_COLUMNNAMES)
        setScanner(profiles)
    }

    private fun setScanner(profiles: Collection<Profile>) {
        scanners.forEach { burpExtender.removeScannerCheck(it) }
        scanners = profiles.map { BurpScannerCheck(it, burpExtender, burpCollaborator) }
        scanners
            .filter { it.profile.enabled }
            .forEach { burpExtender.registerScannerCheck(it) }
    }

    private fun cellUpdated(row: Int, column: Int, source: Any) = when (column) {
        0 -> {
            val scanner = scanners[row]
            val enabled = getValueAt(row, column).toString().toBoolean()
            if (enabled) burpExtender.registerScannerCheck(scanner)
            else burpExtender.removeScannerCheck(scanner)
        }
        else -> {}
    }

    override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
        0 -> clazz<Boolean>()
        else -> super.getColumnClass(columnIndex)
    }

    override fun isCellEditable(row: Int, column: Int) = when (column) {
        0 -> true
        else -> false
    }

    private fun Profile.row() = arrayOf(enabled, name, type, detail.author)

    companion object {
        val PROFILE_COLUMNNAMES = arrayOf("Enabled", "Name", "Type", "Author")
        val PROFILE_COLUMWIDTHS = arrayOf(0.1, 0.6, 0.15, 0.15)
    }
}
