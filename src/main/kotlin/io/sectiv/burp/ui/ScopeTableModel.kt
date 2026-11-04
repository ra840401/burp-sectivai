package io.sectiv.burp.ui

import io.sectiv.burp.core.CapturedExchange
import javax.swing.table.AbstractTableModel

data class ScopeRow(
    val exchange: CapturedExchange,
    var selected: Boolean,
    val hits: Int = 1
)

class ScopeTableModel : AbstractTableModel() {

    private var rows: List<ScopeRow> = emptyList()
    private val columns = listOf("", "Method", "Host", "Path", "Status", "Size", "Type", "Hits")

    fun setRows(rows: List<ScopeRow>) {
        this.rows = rows
        fireTableDataChanged()
    }

    fun rows(): List<ScopeRow> = rows

    fun rowAt(index: Int): ScopeRow? = rows.getOrNull(index)

    fun selectedExchanges(): List<CapturedExchange> = rows.filter { it.selected }.map { it.exchange }

    fun setAllSelected(selected: Boolean) {
        if (rows.isEmpty()) return
        rows.forEach { it.selected = selected }
        fireTableColumnUpdated(0)
    }

    fun fireTableColumnUpdated(column: Int) {
        if (rows.isEmpty()) return
        fireTableChanged(
            javax.swing.event.TableModelEvent(
                this,
                0,
                rows.size - 1,
                column,
                javax.swing.event.TableModelEvent.UPDATE
            )
        )
    }

    override fun getRowCount(): Int = rows.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String = columns[column]

    override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
        0 -> Boolean::class.javaObjectType
        else -> String::class.java
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean = false

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val row = rows[rowIndex]
        val exchange = row.exchange
        return when (columnIndex) {
            0 -> row.selected
            1 -> exchange.method
            2 -> exchange.host
            3 -> exchange.displayPath
            4 -> if (exchange.status > 0) exchange.status.toString() else "-"
            5 -> formatSize(exchange.length)
            6 -> exchange.mime.substringBefore(';').ifBlank { "-" }
            7 -> if (row.hits > 1) row.hits.toString() else ""
            else -> ""
        }
    }

    override fun setValueAt(value: Any?, rowIndex: Int, columnIndex: Int) {
        if (columnIndex != 0) return
        val row = rows.getOrNull(rowIndex) ?: return
        row.selected = value == true
        fireTableCellUpdated(rowIndex, columnIndex)
    }

    private fun formatSize(bytes: Int): String = when {
        bytes <= 0 -> "-"
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
        else -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
    }
}
