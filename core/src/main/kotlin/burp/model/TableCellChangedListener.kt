package burp.model

import javax.swing.event.TableModelEvent
import javax.swing.event.TableModelListener

fun interface TableCellChangedListener : TableModelListener {

    fun updateCell(row: Int, column: Int, source: Any)
    fun insertCell(row: Int, column: Int, source: Any) = println("Cell $row,$column was inserted")
    fun deleteCell(row: Int, column: Int, source: Any) = println("Cell $row,$column was deleted")

    override fun tableChanged(e: TableModelEvent) {
        val column = e.column
        val lastRow = e.lastRow
        val firstRow = e.firstRow
        val source = e.source

        when (e.type) {
            TableModelEvent.UPDATE -> {
                if (firstRow == TableModelEvent.HEADER_ROW) {
                    if (column == TableModelEvent.ALL_COLUMNS) {
                        println("A column was added")
                    } else {
                        println("$column in header changed")
                    }
                } else {
                    if (column == TableModelEvent.ALL_COLUMNS) {
                        println("All columns have changed")
                    } else {
                        (firstRow..lastRow).forEach { updateCell(it, column, source) }
                    }
                }
            }
            TableModelEvent.INSERT -> (firstRow..lastRow).forEach { insertCell(it, column, source) }
            TableModelEvent.DELETE -> (firstRow..lastRow).forEach { deleteCell(it, column, source) }
        }
    }
}
