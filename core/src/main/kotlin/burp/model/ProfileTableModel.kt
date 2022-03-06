package burp.model

import burp.clazz
import javax.swing.table.DefaultTableModel

class ProfileTableModel : DefaultTableModel(PROFILE_COLUMNNAMES, 0) {

    fun setData(profiles: List<Profile>) {
        val columnData = profiles
            .map { it.row() }
            .toTypedArray()
        setDataVector(columnData, PROFILE_COLUMNNAMES)
    }

    override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
        0 -> clazz<Boolean>()
        else -> super.getColumnClass(columnIndex)
    }

    override fun isCellEditable(row: Int, column: Int) = false

    private fun Profile.row() = arrayOf(enabled, name, type, detail.author)

    companion object {
        val PROFILE_COLUMNNAMES = arrayOf("Enabled", "Name", "Type", "Author")
        val PROFILE_COLUMWIDTHS = arrayOf(0.1, 0.6, 0.15, 0.15)
    }
}
