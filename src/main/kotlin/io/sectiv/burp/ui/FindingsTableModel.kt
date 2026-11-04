package io.sectiv.burp.ui

import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.Severity
import java.net.URI
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.table.AbstractTableModel

class FindingsTableModel : AbstractTableModel() {
    private var rows: List<Finding> = emptyList()
    private val columns = listOf(
        "Severity", "Title", "Endpoint", "Method", "Confidence", "Status", "Found"
    )
    private val dateFormat = SimpleDateFormat("MMM d, HH:mm")

    fun setFindings(findings: List<Finding>) {
        rows = findings
        fireTableDataChanged()
    }

    fun findingAt(modelRow: Int): Finding? = rows.getOrNull(modelRow)

    fun indexOf(id: String): Int = rows.indexOfFirst { it.id == id }

    override fun getRowCount(): Int = rows.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String = columns[column]

    override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
        0 -> Severity::class.java
        6 -> Long::class.java
        else -> String::class.java
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val finding = rows[rowIndex]
        return when (columnIndex) {
            0 -> finding.severity
            1 -> finding.title
            2 -> endpoint(finding)
            3 -> finding.method
            4 -> finding.confidence.label
            5 -> finding.status.label
            6 -> finding.createdAt
            else -> ""
        }
    }

    private fun endpoint(finding: Finding): String {
        if (finding.url.isBlank()) return finding.hostLabel
        val uri = runCatching { URI(finding.url) }.getOrNull()
        val host = finding.hostLabel.ifBlank { uri?.host.orEmpty() }
        val path = uri?.rawPath?.takeIf { it.isNotBlank() } ?: "/"
        val query = uri?.rawQuery?.let { "?$it" }.orEmpty()
        return host + path + query
    }

    fun formatDate(millis: Long): String = dateFormat.format(Date(millis))
}
