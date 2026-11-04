package io.sectiv.burp.ui

import burp.api.montoya.MontoyaApi
import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.FindingStatus
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Severity
import io.sectiv.burp.report.ReportMeta
import io.sectiv.burp.report.ReportWriter
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridLayout
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.nio.file.Files
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextField
import javax.swing.RowFilter
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.filechooser.FileNameExtensionFilter
import javax.swing.table.TableRowSorter

class DashboardPanel(
    private val api: MontoyaApi,
    private val store: SectivStore,
    private val theme: SectivTheme,
    private val onGoToScan: () -> Unit
) : JPanel(BorderLayout()) {

    private val model = FindingsTableModel()
    private val table = JTable(model)
    private val sorter = TableRowSorter(model)
    private val detail = FindingDetailPanel(api, theme, store) { refreshFromStore() }
    private val cards = CardLayout()
    private val main = JPanel(cards)

    private val severityCombo = JComboBox(arrayOf("All severities", "Critical", "High", "Medium", "Low", "Info"))
    private val statusCombo = JComboBox(arrayOf("All statuses", "Open", "Triaged", "False positive", "Resolved"))
    private val searchField = PlaceholderTextField(theme, "Search findings…")
    private val footer = JLabel()
    private val countChip = Chip("0", theme.muted, theme.surfaceRaised, theme.monoSmall)
    private val pageHeader: PageHeader
    private val exportButton = SecondaryButton("Export report", theme)
    private val exportJsonButton = SecondaryButton("Export all JSON", theme)
    private val clearAllButton = dangerButton("Clear all", theme)
    private val clearFiltersButton = SecondaryButton("Clear filters", theme)
    private val scanButton = PrimaryButton("Run review", theme)

    private val severityCards = Severity.entries.associateWith { severity ->
        SeverityCard(severity, theme, subtitleFor(severity)) {
            setSeverityFilter(severity)
        }
    }

    private var selectedId: String? = null

    init {
        isOpaque = false
        background = theme.background
        border = EmptyBorder(16, 22, 16, 22)

        pageHeader = PageHeader(
            theme,
            "Workspace overview",
            "Security findings",
            "",
            actions = JPanel(FlowLayout(FlowLayout.RIGHT, 7, 0)).apply {
                isOpaque = false
                add(exportJsonButton)
                add(clearAllButton)
                add(exportButton)
            }
        )

        styleCombo(severityCombo)
        styleCombo(statusCombo)
        SectivUi.styleField(searchField, theme, padding = java.awt.Insets(6, 9, 6, 9), size = 11.5f)
        searchField.toolTipText = "Search title, URL, skill or description"
        searchField.preferredSize = Dimension(210, 30)

        styleTable(table, theme)
        table.rowSorter = sorter
        table.setDefaultRenderer(Severity::class.java, SeverityRenderer(theme))
        table.setDefaultRenderer(String::class.java, TextCellRenderer(theme))
        setupColumns()
        sorter.setComparator(6) { a, b -> (a as? Long ?: 0L).compareTo(b as? Long ?: 0L) }
        sorter.sortKeys = listOf(javax.swing.RowSorter.SortKey(0, javax.swing.SortOrder.ASCENDING))

        table.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) {
                val row = table.selectedRow
                val finding = if (row >= 0) model.findingAt(table.convertRowIndexToModel(row)) else null
                selectedId = finding?.id
                detail.show(finding)
            }
        }

        val pageActions = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(buildSeverityRow(), BorderLayout.NORTH)
        }

        val detailCard = buildDetailPanel().apply {
            preferredSize = Dimension(500, 320)
            minimumSize = Dimension(340, 220)
        }
        val findingsCard = buildFindingsPanel().apply {
            minimumSize = Dimension(420, 220)
        }
        val split = javax.swing.JSplitPane(
            javax.swing.JSplitPane.HORIZONTAL_SPLIT,
            findingsCard,
            detailCard
        ).apply {
            isContinuousLayout = true
            resizeWeight = 0.68
            dividerSize = 5
            isOneTouchExpandable = false
            border = BorderFactory.createEmptyBorder()
            background = theme.borderSoft
        }
        val content = JPanel(BorderLayout(14, 0)).apply {
            isOpaque = false
            add(split, BorderLayout.CENTER)
        }
        val body = JPanel(BorderLayout(0, 12)).apply {
            isOpaque = false
            add(pageActions, BorderLayout.NORTH)
            add(content, BorderLayout.CENTER)
        }

        val empty = EmptyState(
            theme,
            "No findings yet",
            "Pick a goal and a scope of captured traffic, then run your first AI review. Findings are triaged here by severity.",
            "Go to Scan"
        ) { onGoToScan() }

        main.add(body, "main")
        main.add(empty, "empty")
        main.isOpaque = false

        footer.apply {
            font = theme.small
            foreground = theme.muted
            border = EmptyBorder(6, 2, 0, 2)
        }

        add(pageHeader, BorderLayout.NORTH)
        add(main, BorderLayout.CENTER)
        add(footer, BorderLayout.SOUTH)

        severityCombo.addActionListener { applyFilters() }
        statusCombo.addActionListener { applyFilters() }
        clearFiltersButton.addActionListener {
            severityCombo.selectedIndex = 0
            statusCombo.selectedIndex = 0
            searchField.text = ""
            applyFilters()
        }
        searchField.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = applyFilters()
            override fun removeUpdate(e: DocumentEvent) = applyFilters()
            override fun changedUpdate(e: DocumentEvent) = applyFilters()
        })
        exportButton.addActionListener { showExportMenu() }
        exportJsonButton.addActionListener { export("json") }
        clearAllButton.addActionListener {
            val count = store.state().findings.size
            if (count == 0) {
                Dialogs.info(this, "Nothing to clear", "There are no findings to delete.")
            } else if (Dialogs.confirm(this, "Clear all findings", "Delete all $count finding(s)? This cannot be undone.")) {
                store.clearFindings()
                refreshFromStore()
            }
        }
        scanButton.addActionListener { onGoToScan() }

        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && table.selectedRow >= 0) {
                    val finding = model.findingAt(table.convertRowIndexToModel(table.selectedRow))
                    if (finding != null) detail.show(finding)
                }
            }
        })

        store.onChange { SwingUtilities.invokeLater { refreshFromStore() } }
        refreshFromStore()
    }

    private fun setupColumns() {
        table.columnModel.getColumn(0).apply {
            preferredWidth = 104
            minWidth = 92
            maxWidth = 120
        }
        table.columnModel.getColumn(1).preferredWidth = 270
        table.columnModel.getColumn(2).preferredWidth = 280
        table.columnModel.getColumn(3).preferredWidth = 62
        table.columnModel.getColumn(4).apply {
            preferredWidth = 100
            minWidth = 92
        }
        table.columnModel.getColumn(5).preferredWidth = 82
        table.columnModel.getColumn(6).preferredWidth = 100
        table.columnModel.getColumn(5).cellRenderer = StatusRenderer(theme)
        table.columnModel.getColumn(6).cellRenderer = object : javax.swing.table.DefaultTableCellRenderer() {
            override fun getTableCellRendererComponent(
                table: JTable,
                value: Any?,
                isSelected: Boolean,
                hasFocus: Boolean,
                row: Int,
                column: Int
            ): java.awt.Component {
                super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
                text = model.formatDate((value as? Long) ?: 0L)
                font = theme.small
                foreground = if (isSelected) theme.text else theme.faint
                background = if (isSelected) table.selectionBackground else table.background
                border = EmptyBorder(0, 10, 0, 6)
                return this
            }
        }
    }

    private fun buildSeverityRow(): JPanel =
        JPanel(GridLayout(1, Severity.entries.size, 10, 0)).apply {
            isOpaque = false
            border = EmptyBorder(0, 0, 0, 0)
            preferredSize = Dimension(0, 112)
            Severity.entries.forEach { severity -> add(severityCards.getValue(severity)) }
        }

    private fun buildFindingsPanel(): JPanel {
        val panel = RoundedPanel(theme, theme.surface, theme.border, 14)
        panel.layout = BorderLayout()

        val titleRow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(JLabel("Findings").apply {
                font = SectivFonts.semibold(13f)
                foreground = theme.text
            })
            add(countChip)
        }
        val header = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = EmptyBorder(14, 16, 12, 14)
            add(titleRow, BorderLayout.WEST)
            add(JPanel(FlowLayout(FlowLayout.RIGHT, 7, 0)).apply {
                isOpaque = false
                add(SecondaryButton("Export", theme).apply {
                    addActionListener { showExportMenu() }
                })
                add(scanButton)
            }, BorderLayout.EAST)
        }

        val filters = JPanel(FlowLayout(FlowLayout.LEFT, 7, 0)).apply {
            isOpaque = false
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 1, 0, theme.borderSoft),
                EmptyBorder(9, 14, 9, 12)
            )
            add(searchField)
            add(severityCombo)
            add(statusCombo)
            add(clearFiltersButton)
        }

        val tableScroll = JScrollPane(table).apply {
            border = EmptyBorder(0, 0, 0, 0)
            viewport.background = theme.surface
            background = theme.surface
            verticalScrollBar.unitIncrement = 18
            themeScrollBars(this, theme)
        }

        panel.add(header, BorderLayout.NORTH)
        panel.add(JPanel(BorderLayout()).apply {
            isOpaque = false
            add(filters, BorderLayout.NORTH)
            add(tableScroll, BorderLayout.CENTER)
        }, BorderLayout.CENTER)
        return panel
    }

    private fun buildDetailPanel(): JPanel {
        detail.isOpaque = false
        return RoundedPanel(theme, theme.surface, theme.border, 14).apply {
            layout = BorderLayout()
            add(detail, BorderLayout.CENTER)
        }
    }

    private fun styleCombo(combo: JComboBox<String>) {
        SectivUi.styleCombo(combo, theme)
        combo.preferredSize = Dimension(136, 30)
    }

    fun setSeverityFilter(severity: Severity?) {
        severityCombo.selectedIndex = when (severity) {
            Severity.CRITICAL -> 1
            Severity.HIGH -> 2
            Severity.MEDIUM -> 3
            Severity.LOW -> 4
            Severity.INFO -> 5
            null -> 0
        }
        applyFilters()
    }

    private fun refreshFromStore() {
        val state = store.state()
        val findings = state.findings
        val targetId = selectedId
        model.setFindings(findings)
        Severity.entries.forEach { severity ->
            severityCards.getValue(severity).setCount(findings.count { it.severity == severity })
        }
        applyFilters()
        countChip.text = findings.size.toString()
        cards.show(main, if (findings.isEmpty()) "empty" else "main")

        val open = findings.count { it.status == FindingStatus.OPEN }
        val hosts = findings.map { it.hostLabel }.filter { it.isNotBlank() }.distinct().size
        pageHeader.setSubtitle(
            if (findings.isEmpty()) "No findings recorded yet."
            else "${findings.size} findings · $open open · $hosts host(s) · triage locally, export when ready"
        )

        if (findings.isEmpty()) {
            detail.show(null)
            selectedId = null
        } else {
            val restored = if (targetId != null) selectById(targetId) else false
            if (!restored && table.rowCount > 0) table.setRowSelectionInterval(0, 0)
        }
        updateFooter()
    }

    private fun selectById(id: String): Boolean {
        val modelRow = model.indexOf(id)
        if (modelRow < 0) return false
        val viewRow = table.convertRowIndexToView(modelRow)
        if (viewRow < 0) return false
        table.setRowSelectionInterval(viewRow, viewRow)
        table.scrollRectToVisible(table.getCellRect(viewRow, 0, true))
        return true
    }

    private fun applyFilters() {
        val severity = when (severityCombo.selectedIndex) {
            1 -> Severity.CRITICAL
            2 -> Severity.HIGH
            3 -> Severity.MEDIUM
            4 -> Severity.LOW
            5 -> Severity.INFO
            else -> null
        }
        val status = when (statusCombo.selectedIndex) {
            1 -> FindingStatus.OPEN
            2 -> FindingStatus.TRIAGED
            3 -> FindingStatus.FALSE_POSITIVE
            4 -> FindingStatus.RESOLVED
            else -> null
        }
        val query = searchField.text.trim().lowercase()

        if (severity == null && status == null && query.isEmpty()) {
            sorter.rowFilter = null
        } else {
            sorter.rowFilter = object : RowFilter<FindingsTableModel, Int>() {
                override fun include(entry: RowFilter.Entry<out FindingsTableModel, out Int>): Boolean {
                    val finding = model.findingAt(entry.identifier) ?: return false
                    if (severity != null && finding.severity != severity) return false
                    if (status != null && finding.status != status) return false
                    if (query.isNotEmpty()) {
                        val haystack = listOf(
                            finding.title,
                            finding.url,
                            finding.host,
                            finding.skillName,
                            finding.description,
                            finding.cwe
                        ).joinToString(" ").lowercase()
                        if (!haystack.contains(query)) return false
                    }
                    return true
                }
            }
        }
        updateFooter()
    }

    private fun updateFooter() {
        val all = store.state().findings
        val shown = table.rowCount
        val open = all.count { it.status == FindingStatus.OPEN }
        footer.text = when {
            all.isEmpty() -> "No findings yet"
            shown == 0 -> "${all.size} findings · none match the current filters"
            else -> "${all.size} findings · $shown shown · $open open"
        }
    }

    private fun showExportMenu() {
        val menu = JPopupMenu().apply {
            background = theme.surfaceAlt
            border = BorderFactory.createLineBorder(theme.border)
        }
        listOf(
            "HTML report…" to "html",
            "Markdown report…" to "md",
            "JSON export…" to "json"
        ).forEach { (label, format) ->
            menu.add(javax.swing.JMenuItem(label).apply {
                font = theme.small
                background = theme.surfaceAlt
                foreground = theme.text
                addActionListener { export(format) }
            })
        }
        menu.show(exportButton, 0, exportButton.height + 2)
    }

    private fun export(format: String) {
        val findings = store.state().findings
        if (findings.isEmpty()) {
            Dialogs.info(this, "Nothing to export", "There are no findings to export yet.")
            return
        }
        val extension = format
        val stamp = SimpleDateFormat("yyyyMMdd-HHmm").format(Date())
        val chooser = JFileChooser().apply {
            dialogTitle = "Export Sectiv findings"
            selectedFile = java.io.File("sectiv-findings-$stamp.$extension")
            fileFilter = FileNameExtensionFilter(
                when (format) {
                    "html" -> "HTML report (*.html)"
                    "md" -> "Markdown (*.md)"
                    else -> "JSON (*.json)"
                },
                extension
            )
        }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        var file = chooser.selectedFile
        if (!file.name.lowercase().endsWith(".$extension")) {
            file = java.io.File(file.parentFile, file.name + ".$extension")
        }

        val provider = store.state().settings.activeProvider()
        val meta = ReportMeta(
            title = "Sectiv Security Review",
            target = findings.map { it.hostLabel }.filter { it.isNotBlank() }.distinct().joinToString(", "),
            provider = "${provider.name} · ${provider.model}"
        )
        val content = when (format) {
            "html" -> ReportWriter.toHtml(findings, meta)
            "md" -> ReportWriter.toMarkdown(findings, meta)
            else -> ReportWriter.toJson(findings, meta)
        }
        try {
            Files.writeString(file.toPath(), content)
            Dialogs.info(this, "Report exported", "Saved to:\n${file.absolutePath}")
        } catch (e: Exception) {
            Dialogs.error(this, "Export failed", e.message ?: e.javaClass.simpleName)
        }
    }

    private fun subtitleFor(severity: Severity): String = when (severity) {
        Severity.CRITICAL -> "needs immediate review"
        Severity.HIGH -> "privilege or tenant impact"
        Severity.MEDIUM -> "needs a precondition"
        Severity.LOW -> "defence in depth"
        Severity.INFO -> "observation only"
    }
}
