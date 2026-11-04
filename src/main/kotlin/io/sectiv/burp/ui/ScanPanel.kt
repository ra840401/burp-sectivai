package io.sectiv.burp.ui

import burp.api.montoya.MontoyaApi
import io.sectiv.burp.core.CapturedExchange
import io.sectiv.burp.core.IdentityContextParser
import io.sectiv.burp.core.IdentityPair
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Severity
import io.sectiv.burp.core.Skill
import io.sectiv.burp.scan.HistoryCollection
import io.sectiv.burp.scan.HistoryCollector
import io.sectiv.burp.scan.HistorySource
import io.sectiv.burp.scan.LogLevel
import io.sectiv.burp.scan.ScanHandle
import io.sectiv.burp.scan.ScanListener
import io.sectiv.burp.scan.ScanRequest
import io.sectiv.burp.scan.ScanStage
import io.sectiv.burp.scan.ScanSummary
import io.sectiv.burp.scan.ScanEngine
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Cursor
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Insets
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JProgressBar
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListCellRenderer
import javax.swing.SwingUtilities
import javax.swing.SwingWorker
import javax.swing.Timer
import javax.swing.border.EmptyBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.event.TableModelEvent
import javax.swing.event.TableModelListener
import javax.swing.table.DefaultTableCellRenderer
import kotlin.math.ceil

class ScanPanel(
    private val api: MontoyaApi,
    private val store: SectivStore,
    private val engine: ScanEngine,
    private val theme: SectivTheme,
    private val onOpenSettings: () -> Unit,
    private val onOpenSkills: (String?) -> Unit
) : JPanel(BorderLayout()), AutoCloseable {

    private val collector = HistoryCollector(api)

    private val sourceCombo = JComboBox(arrayOf(HistorySource.PROXY.label, HistorySource.SITEMAP.label))
    private val refreshButton = ghostButton("Refresh", theme)
    private val scopeFilter = PlaceholderTextField(theme, "Filter host, path, method…")
    private val inScopeOnly = JCheckBox("Burp scope only")
    private val dedupeCheck = JCheckBox("Collapse duplicates")
    private val removeStaticCheck = JCheckBox("Remove static files")
    private val selectAllButton = ghostButton("Select all", theme)
    private val selectNoneButton = ghostButton("None", theme)
    private val selectScopeButton = ghostButton("In scope", theme)
    private val scopeCount = JLabel("0 selected")
    private val scopeModel = ScopeTableModel()
    private val scopeTable = JTable(scopeModel)
    private val scopeCards = java.awt.CardLayout()
    private val scopeBody = JPanel(scopeCards)
    private val scopeEmptyLabel = WrapLabel("", theme.base, theme.muted, 480, center = true)

    private val skillCombo = JComboBox<Skill>()
    private val allSkillsCheck = JCheckBox("Run all enabled skills")
    private val skillDescription = PlaceholderTextArea(theme, "Select a skill to see what it looks for.")
    private val editSkillButton = ghostButton("Edit skill", theme)

    private val authArea = PlaceholderTextArea(
        theme,
        "User A\n  email: alice@example.com\n  Cookie: session=...\n  Authorization: Bearer ...\n\nUser B\n  email: bob@example.com\n  Cookie: session=...\n  Authorization: Bearer ..."
    )
    private val templateButton = ghostButton("Insert template", theme)
    private val clearAuthButton = ghostButton("Clear", theme)
    private val identityLabel = WrapLabel("", theme.small, theme.muted, 430)
    private val identityTimer = Timer(350) { updateIdentityStatus() }.apply { isRepeats = false }
    private val authSaveTimer = Timer(700) {
        if (store.state().authContext != authArea.text) store.setAuthContext(authArea.text)
    }.apply { isRepeats = false }

    private val activeCheck = JCheckBox("Verify with identity swap")
    private val activeHint = WrapLabel(
        "Replays selected requests with User B's credentials and compares responses. Sends traffic through Burp; state-changing methods stay disabled unless enabled in Settings.",
        theme.tiny,
        theme.faint,
        420
    )
    private val settingsButton = ghostButton("API settings", theme)
    private val providerLabel = JLabel()
    private val estimateLabel = JLabel()
    private val runButton = PrimaryButton("Run scan", theme)
    private val stopButton = ghostButton("Stop", theme)
    private val progress = JProgressBar(0, 100)
    private val statusLabel = JLabel("Ready")
    private val log = LogPane(theme)
    private val clearLogButton = ghostButton("Clear log", theme)

    private var loaded: List<CapturedExchange> = emptyList()
    private var selectedIds = mutableSetOf<String>()
    private var skillsCache: List<Skill> = emptyList()
    private var providerCache: String = ""
    private var identities: IdentityPair = IdentityPair.EMPTY
    private var handle: ScanHandle? = null
    private var running = false
    private var loadToken = 0
    private var firstLoad = true
    private var suppressModelEvents = false

    init {
        isOpaque = false
        background = theme.background
        border = EmptyBorder(16, 22, 16, 22)

        SectivUi.styleCombo(sourceCombo, theme)
        sourceCombo.preferredSize = Dimension(150, 30)
        SectivUi.styleField(scopeFilter, theme, padding = java.awt.Insets(5, 8, 5, 8), size = 11f)
        scopeFilter.toolTipText = "Filter by host, path, method or status"
        scopeFilter.preferredSize = Dimension(230, 30)
        SectivUi.styleCheck(inScopeOnly, theme)
        SectivUi.styleCheck(dedupeCheck, theme)
        SectivUi.styleCheck(removeStaticCheck, theme)
        SectivUi.styleCheck(allSkillsCheck, theme)
        SectivUi.styleCheck(activeCheck, theme)

        val pageHeader = PageHeader(
            theme,
            "New review",
            "Run a review",
            "Select captured traffic, a goal, and optional identities for BAC/IDOR checks."
        )

        val scopeSection = buildScopeSection().apply {
            preferredSize = Dimension(0, 300)
            minimumSize = Dimension(0, 150)
        }
        val bottomSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            buildConfigScroll(),
            buildRunSection()
        ).apply {
            isContinuousLayout = true
            resizeWeight = 0.60
            dividerSize = 5
            isOneTouchExpandable = false
            border = BorderFactory.createEmptyBorder()
            background = theme.borderSoft
        }
        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, scopeSection, bottomSplit).apply {
            isContinuousLayout = true
            resizeWeight = 0.38
            dividerSize = 5
            isOneTouchExpandable = false
            border = BorderFactory.createEmptyBorder()
            background = theme.borderSoft
        }
        val mainCard = RoundedPanel(theme, theme.surface, theme.border, 14).apply {
            layout = BorderLayout()
            add(split, BorderLayout.CENTER)
        }

        add(pageHeader, BorderLayout.NORTH)
        add(mainCard, BorderLayout.CENTER)

        wireEvents()
        refreshSkills()
        refreshProviderLabel()
        authArea.text = store.state().authContext
        updateIdentityStatus()
        updateSummary()

        themeScrollBars(this, theme)
        store.onChange { SwingUtilities.invokeLater { refreshSkills(); refreshProviderLabel() } }
        javax.swing.Timer(350) { refreshHistory() }.apply { isRepeats = false }.start()
    }

    private fun buildScopeSection(): JPanel {
        val section = JPanel(BorderLayout(0, 8)).apply {
            isOpaque = false
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.borderSoft),
                EmptyBorder(14, 16, 12, 16)
            )
        }

        val titleRow = JPanel(BorderLayout()).apply {
            isOpaque = false
            val left = JPanel(FlowLayout(FlowLayout.LEFT, 9, 0)).apply {
                isOpaque = false
                add(StepBadge("1", theme))
                add(JLabel("Target scope").apply { font = SectivFonts.semibold(13f); foreground = theme.text })
                add(sourceCombo)
                add(refreshButton)
            }
            add(left, BorderLayout.WEST)
            scopeCount.font = theme.monoSmall
            scopeCount.foreground = theme.faint
            add(scopeCount, BorderLayout.EAST)
        }

        val filterRow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(scopeFilter)
            add(inScopeOnly)
            add(dedupeCheck)
            add(removeStaticCheck)
            add(Box.createHorizontalStrut(6))
            add(selectAllButton)
            add(selectNoneButton)
            add(selectScopeButton)
        }

        val top = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(titleRow)
            add(Box.createVerticalStrut(7))
            add(filterRow)
        }

        styleTable(scopeTable, theme)
        scopeTable.setDefaultRenderer(Boolean::class.javaObjectType, BooleanRenderer(theme))
        scopeTable.setDefaultRenderer(String::class.java, TextCellRenderer(theme))
        scopeTable.rowHeight = 31
        scopeTable.columnModel.getColumn(0).apply {
            preferredWidth = 36
            minWidth = 36
            maxWidth = 36
            resizable = false
        }
        scopeTable.columnModel.getColumn(1).preferredWidth = 72
        scopeTable.columnModel.getColumn(2).preferredWidth = 200
        scopeTable.columnModel.getColumn(3).preferredWidth = 440
        scopeTable.columnModel.getColumn(4).preferredWidth = 62
        scopeTable.columnModel.getColumn(5).preferredWidth = 88
        scopeTable.columnModel.getColumn(6).preferredWidth = 100
        scopeTable.columnModel.getColumn(7).preferredWidth = 48
        scopeTable.columnModel.getColumn(7).maxWidth = 60

        val emptyPanel = JPanel(BorderLayout()).apply {
            isOpaque = true
            background = theme.surface
            add(scopeEmptyLabel, BorderLayout.CENTER)
        }
        scopeBody.add(scrollPane(scopeTable, theme), "table")
        scopeBody.add(emptyPanel, "empty")
        section.add(top, BorderLayout.NORTH)
        section.add(scopeBody, BorderLayout.CENTER)
        return section
    }

    private fun buildConfigScroll(): JComponent {
        val content = ScrollableColumn().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = EmptyBorder(0, 0, 0, 4)
        }

        // Review goal
        val goal = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.borderSoft),
                EmptyBorder(14, 16, 12, 16)
            )
        }
        val goalHead = JPanel(BorderLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(StepBadge("2", theme), BorderLayout.WEST)
            add(JPanel().apply {
                isOpaque = false
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                border = EmptyBorder(0, 9, 0, 0)
                add(JLabel("Review goal").apply { font = SectivFonts.semibold(13f); foreground = theme.text })
                add(JLabel("One skill shapes the AI prompt.").apply { font = theme.tiny; foreground = theme.faint })
            }, BorderLayout.CENTER)
        }
        SectivUi.styleCombo(skillCombo, theme)
        skillCombo.alignmentX = LEFT_ALIGNMENT
        skillCombo.maximumSize = Dimension(Int.MAX_VALUE, 34)
        skillCombo.preferredSize = Dimension(420, 34)
        skillCombo.renderer = SkillRenderer(theme)
        allSkillsCheck.alignmentX = LEFT_ALIGNMENT
        skillDescription.isEditable = false
        skillDescription.rows = 3
        SectivUi.styleField(skillDescription, theme, fill = theme.backgroundDeep, padding = java.awt.Insets(7, 9, 7, 9), size = 10.5f)
        skillDescription.alignmentX = LEFT_ALIGNMENT
        skillDescription.maximumSize = Dimension(Int.MAX_VALUE, 96)
        editSkillButton.alignmentX = LEFT_ALIGNMENT
        goal.add(goalHead)
        goal.add(Box.createVerticalStrut(10))
        goal.add(skillCombo)
        goal.add(Box.createVerticalStrut(4))
        goal.add(allSkillsCheck)
        goal.add(Box.createVerticalStrut(8))
        goal.add(skillDescription)
        goal.add(Box.createVerticalStrut(8))
        goal.add(editSkillButton)

        // Identity context
        val identity = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = EmptyBorder(14, 16, 12, 16)
        }
        val identityHead = JPanel(BorderLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(StepBadge("3", theme), BorderLayout.WEST)
            add(JPanel().apply {
                isOpaque = false
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                border = EmptyBorder(0, 9, 0, 0)
                add(JLabel("Identity context").apply { font = SectivFonts.semibold(13f); foreground = theme.text })
                add(JLabel("Paste two accounts. Cookies are masked before prompting.").apply { font = theme.tiny; foreground = theme.faint })
            }, BorderLayout.CENTER)
        }
        val identityHelp = htmlLabel(
            "The AI uses this to reason about BOLA/IDOR, and Sectiv can replay requests with the second identity.",
            theme.small,
            theme.muted,
            430
        ).apply { alignmentX = LEFT_ALIGNMENT }
        authArea.isOpaque = false
        authArea.background = theme.backgroundDeep
        authArea.foreground = theme.text
        authArea.font = theme.monoSmall
        authArea.border = EmptyBorder(9, 11, 9, 11)
        val authScroll = JScrollPane(authArea).apply {
            border = RoundedBorder(theme.backgroundDeep, theme.border, 9)
            preferredSize = Dimension(430, 160)
            maximumSize = Dimension(Int.MAX_VALUE, 170)
            viewport.background = theme.backgroundDeep
            alignmentX = LEFT_ALIGNMENT
            themeScrollBars(this, theme)
        }
        val authButtons = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(templateButton)
            add(clearAuthButton)
        }
        identityLabel.alignmentX = LEFT_ALIGNMENT
        activeCheck.alignmentX = LEFT_ALIGNMENT
        activeHint.alignmentX = LEFT_ALIGNMENT

        identity.add(identityHead)
        identity.add(Box.createVerticalStrut(8))
        identity.add(identityHelp)
        identity.add(Box.createVerticalStrut(8))
        identity.add(authScroll)
        identity.add(Box.createVerticalStrut(7))
        identity.add(authButtons)
        identity.add(Box.createVerticalStrut(6))
        identity.add(identityLabel)
        identity.add(Box.createVerticalStrut(8))
        identity.add(activeCheck)
        identity.add(Box.createVerticalStrut(3))
        identity.add(activeHint)

        content.add(goal)
        content.add(identity)
        content.add(Box.createVerticalGlue())

        return JScrollPane(content).apply {
            border = BorderFactory.createEmptyBorder()
            viewport.background = theme.surface
            background = theme.surface
            verticalScrollBar.unitIncrement = 18
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
        }
    }

    private fun buildRunSection(): JComponent {
        val section = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 1, 0, 0, theme.borderSoft),
                EmptyBorder(14, 16, 14, 14)
            )
        }

        val providerRow = JPanel(FlowLayout(FlowLayout.LEFT, 7, 0)).apply {
            isOpaque = false
            add(JLabel("●").apply { font = theme.tiny; foreground = theme.accent })
            add(JLabel("Provider").apply { font = theme.tiny; foreground = theme.faint })
            providerLabel.font = SectivFonts.semibold(11.5f)
            providerLabel.foreground = theme.textSoft
            add(providerLabel)
            add(settingsButton)
        }

        estimateLabel.font = theme.monoSmall
        estimateLabel.foreground = theme.faint

        val buttons = JPanel(FlowLayout(FlowLayout.LEFT, 7, 0)).apply {
            isOpaque = false
            add(runButton)
            stopButton.isEnabled = false
            add(stopButton)
        }

        progress.isStringPainted = false
        progress.isBorderPainted = false
        progress.background = theme.backgroundDeep
        progress.foreground = theme.accent
        progress.preferredSize = Dimension(100, 4)

        statusLabel.font = theme.small
        statusLabel.foreground = theme.muted

        val top = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(providerRow)
            add(Box.createVerticalStrut(4))
            add(estimateLabel)
            add(Box.createVerticalStrut(10))
            add(buttons)
            add(Box.createVerticalStrut(10))
            add(progress)
            add(Box.createVerticalStrut(6))
            add(statusLabel)
        }

        val logHeader = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = EmptyBorder(12, 2, 7, 2)
            add(JLabel("RUN LOG").apply { font = theme.eyebrow; foreground = theme.faint }, BorderLayout.WEST)
            add(clearLogButton, BorderLayout.EAST)
        }
        val logPanel = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(logHeader, BorderLayout.NORTH)
            add(scrollPane(log, theme), BorderLayout.CENTER)
        }

        section.add(top, BorderLayout.NORTH)
        section.add(logPanel, BorderLayout.CENTER)
        return section
    }

    private fun wireEvents() {
        refreshButton.addActionListener { refreshHistory() }
        sourceCombo.addActionListener { if (!isLoading()) refreshHistory() }
        scopeFilter.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = rebuildRows()
            override fun removeUpdate(e: DocumentEvent) = rebuildRows()
            override fun changedUpdate(e: DocumentEvent) = rebuildRows()
        })
        inScopeOnly.addActionListener { rebuildRows() }
        dedupeCheck.addActionListener { rebuildRows() }
        removeStaticCheck.addActionListener { rebuildRows() }
        selectAllButton.addActionListener {
            suppressModelEvents = true
            scopeModel.setAllSelected(true)
            suppressModelEvents = false
            syncSelection(); updateSummary()
        }
        selectNoneButton.addActionListener {
            suppressModelEvents = true
            scopeModel.setAllSelected(false)
            suppressModelEvents = false
            syncSelection(); updateSummary()
        }
        selectScopeButton.addActionListener { selectInScope() }

        scopeTable.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                val row = scopeTable.rowAtPoint(e.point)
                val column = scopeTable.columnAtPoint(e.point)
                if (row >= 0 && column == 0) {
                    val current = scopeModel.getValueAt(row, 0) as? Boolean ?: false
                    scopeModel.setValueAt(!current, row, 0)
                }
            }
        })
        scopeModel.addTableModelListener(object : TableModelListener {
            override fun tableChanged(e: TableModelEvent) {
                if (suppressModelEvents) return
                if (e.type == TableModelEvent.UPDATE && e.firstRow >= 0) {
                    syncSelection()
                    updateSummary()
                }
            }
        })

        skillCombo.addActionListener { updateSkillDescription(); updateSummary() }
        allSkillsCheck.addActionListener {
            skillCombo.isEnabled = !allSkillsCheck.isSelected && skillCombo.itemCount > 0
            updateSkillDescription()
            updateSummary()
        }
        editSkillButton.addActionListener {
            val id = (skillCombo.selectedItem as? Skill)?.id
            onOpenSkills(id)
        }

        authArea.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) {
                identityTimer.restart()
                authSaveTimer.restart()
            }

            override fun removeUpdate(e: DocumentEvent) {
                identityTimer.restart()
                authSaveTimer.restart()
            }

            override fun changedUpdate(e: DocumentEvent) {
                identityTimer.restart()
                authSaveTimer.restart()
            }
        })
        templateButton.addActionListener {
            if (authArea.text.isBlank()) {
                authArea.text = IdentityContextParser.TEMPLATE
            } else {
                authArea.text = authArea.text.trimEnd() + "\n\n" + IdentityContextParser.TEMPLATE
            }
            authArea.requestFocusInWindow()
        }
        clearAuthButton.addActionListener { authArea.text = "" }
        settingsButton.addActionListener { onOpenSettings() }
        runButton.addActionListener { runScan() }
        stopButton.addActionListener { stopScan() }
        clearLogButton.addActionListener { log.clearLog() }
    }

    private fun refreshHistory() {
        val token = ++loadToken
        val source = HistorySource.from(sourceCombo.selectedItem as? String)
        setLoading(true)
        object : SwingWorker<HistoryCollection, Void>() {
            override fun doInBackground(): HistoryCollection = collector.collect(source)
            override fun done() {
                if (token != loadToken) return
                var autoSelect = false
                try {
                    val result = get()
                    loaded = result.exchanges
                    val suffix = if (result.truncated) " (showing last ${result.exchanges.size} of ${result.totalAvailable})" else ""
                    log.append(LogLevel.INFO, "Loaded ${result.exchanges.size} ${source.label.lowercase()} entries$suffix.")
                    autoSelect = firstLoad && store.state().settings.autoSelectInScope
                    firstLoad = false
                } catch (e: Exception) {
                    log.append(LogLevel.ERROR, "Could not load ${source.label}: ${rootMessage(e)}")
                } finally {
                    setLoading(false)
                    rebuildRows()
                    if (autoSelect) selectInScope()
                }
            }
        }.execute()
    }

    private fun rebuildRows() {
        val query = scopeFilter.text.trim().lowercase()
        val onlyScope = inScopeOnly.isSelected
        val dropStatic = removeStaticCheck.isSelected
        val filtered = loaded.filter { exchange ->
            if (query.isNotEmpty()) {
                val haystack = "${exchange.method} ${exchange.host} ${exchange.path} ${exchange.status} ${exchange.url}".lowercase()
                if (!haystack.contains(query)) return@filter false
            }
            if (onlyScope && !runCatching { api.scope().isInScope(exchange.url) }.getOrDefault(false)) {
                return@filter false
            }
            if (dropStatic && isStaticAsset(exchange.path)) {
                return@filter false
            }
            true
        }

        val rows = if (dedupeCheck.isSelected) {
            val grouped = LinkedHashMap<String, ScopeRow>()
            for (exchange in filtered.sortedBy { it.timestamp }) {
                val key = "${exchange.method}|${exchange.host}|${exchange.path.substringBefore('?')}"
                val existing = grouped[key]
                grouped[key] = if (existing == null) {
                    ScopeRow(exchange, exchange.id in selectedIds, 1)
                } else {
                    ScopeRow(exchange, existing.selected || exchange.id in selectedIds, existing.hits + 1)
                }
            }
            grouped.values.toList()
        } else {
            filtered.map { ScopeRow(it, it.id in selectedIds, 1) }
        }

        suppressModelEvents = true
        scopeModel.setRows(rows)
        suppressModelEvents = false
        syncSelection()
        updateSummary()
        val isEmpty = rows.isEmpty()
        scopeCards.show(scopeBody, if (isEmpty) "empty" else "table")
        if (isEmpty) {
            scopeEmptyLabel.setText(
                if (loaded.isEmpty()) {
                    "No captured traffic yet.\n\nBrowse the target through Burp, then click Refresh."
                } else {
                    "No requests match the current filter."
                }
            )
        }
    }

    private fun selectInScope() {
        suppressModelEvents = true
        for (row in scopeModel.rows()) {
            row.selected = runCatching { api.scope().isInScope(row.exchange.url) }.getOrDefault(false)
        }
        scopeModel.fireTableColumnUpdated(0)
        suppressModelEvents = false
        syncSelection()
        updateSummary()
    }

    private fun syncSelection() {
        selectedIds = scopeModel.rows().filter { it.selected }.mapTo(mutableSetOf()) { it.exchange.id }
    }

    private fun updateSummary() {
        val selected = scopeModel.selectedExchanges()
        val shown = scopeModel.rowCount
        scopeCount.text = "${selected.size} selected / $shown shown"
        scopeCount.foreground = if (selected.isEmpty()) theme.muted else theme.text

        val settings = store.state().settings
        val skills = chosenSkills()
        val chars = selected.sumOf {
            minOf(it.requestRaw.length, 9000) + minOf(it.responseRaw.length, settings.maxResponseChars)
        }
        val budget = (settings.chunkChars - 3000 - authArea.text.length).coerceAtLeast(5000)
        val aiCalls = if (selected.isEmpty() || skills.isEmpty()) 0 else {
            maxOf(skills.size, ceil(chars.toDouble() / budget).toInt() * skills.size)
        }
        estimateLabel.text = buildString {
            append("${selected.size} request(s) · ${formatChars(chars)}")
            if (skills.isNotEmpty()) append(" · ~$aiCalls AI call(s)")
            if (activeCheck.isSelected && selected.isNotEmpty()) {
                val allowed = if (settings.allowStateChangingChecks) {
                    setOf("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
                } else {
                    setOf("GET", "HEAD", "OPTIONS")
                }
                val eligible = selected.count {
                    it.status in 200..299 && it.method.uppercase() in allowed
                }
                append(" · up to $eligible swap request(s)")
            }
        }
        estimateLabel.toolTipText = "Approximate prompt size after masking. The exact number of calls depends on chunking."

        if (!running) {
            runButton.isEnabled = selected.isNotEmpty() && skills.isNotEmpty()
        }
    }

    private fun chosenSkills(): List<Skill> {
        val enabled = store.state().skills.filter { it.enabled }
        if (allSkillsCheck.isSelected) return enabled
        val selected = skillCombo.selectedItem as? Skill
        return if (selected != null && selected.enabled) listOf(selected) else emptyList()
    }

    private fun refreshSkills() {
        val enabled = store.state().skills.filter { it.enabled }
        if (enabled == skillsCache) return
        skillsCache = enabled
        val selectedId = (skillCombo.selectedItem as? Skill)?.id
        skillCombo.removeAllItems()
        enabled.forEach { skillCombo.addItem(it) }
        val restore = enabled.firstOrNull { it.id == selectedId } ?: enabled.firstOrNull()
        if (restore != null) skillCombo.selectedItem = restore
        skillCombo.isEnabled = !allSkillsCheck.isSelected && enabled.isNotEmpty()
        updateSkillDescription()
        updateSummary()
    }

    private fun updateSkillDescription() {
        if (allSkillsCheck.isSelected) {
            val count = store.state().skills.count { it.enabled }
            skillDescription.text = "Full sweep: $count enabled skill(s) will review the selected traffic. Findings are still scoped to each skill."
            return
        }
        val skill = skillCombo.selectedItem as? Skill
        skillDescription.text = when {
            skill == null -> "No enabled skills. Add one in the Skills tab."
            else -> buildString {
                if (skill.description.isNotBlank()) append(skill.description)
                append("\n\nCategory: ").append(skill.category)
                append(" · ").append(skill.instructions.length).append(" characters of instructions")
            }
        }
    }

    private fun refreshProviderLabel() {
        val settings = store.state().settings
        val provider = settings.activeProvider()
        val cacheKey = "${provider.id}|${provider.name}|${provider.model}|${provider.apiKey.isNotBlank()}|${provider.baseUrl}"
        if (cacheKey == providerCache) return
        providerCache = cacheKey
        val missingKey = provider.requiresApiKey && provider.apiKey.isBlank()
        providerLabel.text = "${provider.name} · ${provider.model.ifBlank { "no model" }}"
        providerLabel.foreground = if (missingKey) theme.warning else theme.text
        providerLabel.toolTipText = when {
            missingKey -> "No API key configured for ${provider.name}."
            provider.baseUrl.isBlank() -> "No base URL configured."
            else -> provider.baseUrl
        }
    }

    private fun updateIdentityStatus() {
        identities = IdentityContextParser.parse(authArea.text)
        val swappable = identities.swappable
        val plain = when {
            identities.a == null && identities.b == null ->
                "No identities detected — BAC/IDOR review will be passive."
            swappable -> "Identity swap ready · ${identities.summary()}"
            identities.hasCompleteCredentials ->
                "Both identities have credentials, but no Cookie/Authorization header can be swapped."
            else -> "Partial context · ${identities.summary()}. Add a Cookie or Authorization for both users."
        }
        identityLabel.setText(plain)
        identityLabel.foreground = when {
            swappable -> theme.success
            identities.hasAnyIdentity -> theme.warning
            else -> theme.muted
        }
        identityLabel.toolTipText = if (authArea.text.isBlank()) {
            "Tip: use the template and replace the placeholder values, or paste notes such as \"User A cookie is: session=...\"."
        } else {
            plain
        }
        activeCheck.isEnabled = swappable
        if (!swappable && activeCheck.isSelected) activeCheck.isSelected = false
        updateSummary()
    }

    private fun runScan() {
        if (running) return
        val selected = scopeModel.selectedExchanges()
        if (selected.isEmpty()) {
            Dialogs.info(this, "Select a scope", "Tick at least one request from Burp's history to review.")
            return
        }
        val skills = chosenSkills()
        if (skills.isEmpty()) {
            Dialogs.info(this, "Select a skill", "Add or enable a skill in the Skills tab, then choose it as the review goal.")
            return
        }
        val settings = store.state().settings
        val provider = settings.activeProvider()
        if (provider.requiresApiKey && provider.apiKey.isBlank()) {
            val open = Dialogs.confirm(
                this,
                "API key required",
                "${provider.name} has no API key configured.\n\nOpen Settings now?"
            )
            if (open) onOpenSettings()
            return
        }
        if (provider.baseUrl.isBlank() || provider.model.isBlank()) {
            Dialogs.error(this, "Provider not configured", "Set a base URL and model for ${provider.name} in Settings.")
            return
        }

        val parsedIdentities = IdentityContextParser.parse(authArea.text)
        var swap = activeCheck.isSelected
        if (swap && !parsedIdentities.swappable) {
            Dialogs.info(
                this,
                "Identity swap unavailable",
                "Add a Cookie or Authorization value for both User A and User B, or disable the identity-swap option."
            )
            return
        }
        if (swap) {
            val eligible = selected.count {
                it.status in 200..299 && it.method.uppercase() in
                    if (settings.allowStateChangingChecks) {
                        setOf("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
                    } else {
                        setOf("GET", "HEAD", "OPTIONS")
                    }
            }
            if (eligible == 0) {
                swap = false
                log.append(
                    LogLevel.WARN,
                    "No eligible success responses for identity swap; running the AI review only."
                )
            } else {
                val proceed = Dialogs.confirm(
                    this,
                    "Run identity-swap checks?",
                    "Sectiv will send up to ${minOf(eligible, settings.maxSwapRequests)} request(s) through Burp " +
                        "using User B's credentials and compare the responses with User A's.\n\n" +
                        "Only GET/HEAD/OPTIONS are used unless state-changing checks are enabled in Settings. " +
                        "Continue?"
                )
                if (!proceed) return
            }
        }

        val request = ScanRequest(
            exchanges = selected,
            skills = skills,
            authContext = authArea.text,
            provider = provider,
            settings = settings,
            identitySwap = swap
        )

        setRunning(true)
        progress.value = 0
        statusLabel.text = "Preparing review…"
        log.append(LogLevel.INFO, "Starting ${if (skills.size == 1) skills.first().name else "full sweep"} on ${selected.size} request(s) with ${provider.name}.")
        try {
            handle = engine.scan(request, listener)
        } catch (e: Exception) {
            setRunning(false)
            statusLabel.text = "Could not start scan"
            log.append(LogLevel.ERROR, e.message ?: e.javaClass.simpleName)
            Dialogs.error(this, "Could not start scan", e.message ?: e.javaClass.simpleName)
        }
    }

    private fun stopScan() {
        val active = handle ?: return
        active.cancel()
        stopButton.isEnabled = false
        statusLabel.text = "Stopping after the current request…"
        log.append(LogLevel.WARN, "Stop requested. Waiting for the in-flight request to finish…")
    }

    private val listener = object : ScanListener {
        override fun onLog(message: String, level: LogLevel) {
            SwingUtilities.invokeLater {
                log.append(level, message)
                if (level == LogLevel.ERROR) statusLabel.text = "Error — see run log"
            }
        }

        override fun onProgress(stage: ScanStage, message: String, done: Int, total: Int) {
            SwingUtilities.invokeLater {
                statusLabel.text = message
                if (total > 0) {
                    progress.value = ((done.toDouble() / total) * 100).toInt().coerceIn(0, 100)
                }
                if (stage == ScanStage.FINISHED) progress.value = 100
            }
        }

        override fun onFindingsAdded(count: Int) {
            SwingUtilities.invokeLater {
                statusLabel.text = "$count new finding(s) added to the dashboard"
            }
        }

        override fun onFinished(summary: ScanSummary) {
            SwingUtilities.invokeLater {
                setRunning(false)
                progress.value = 100
                handle = null
                val secs = summary.durationMs / 1000
                statusLabel.text = if (summary.cancelled) {
                    "Stopped · ${summary.addedFindings} finding(s) added"
                } else {
                    "Complete · ${summary.addedFindings} finding(s) added in ${secs}s"
                }
                log.append(
                    if (summary.cancelled) LogLevel.WARN else LogLevel.SUCCESS,
                    "Finished: ${summary.addedFindings} added, ${summary.duplicateFindings} duplicate(s), " +
                        "${summary.aiCalls} AI call(s) (${summary.failedAiCalls} failed), " +
                        "${summary.swapRequests} swap request(s) sent. ${secs}s." +
                        if (summary.cancelled) " Cancelled." else ""
                )
            }
        }

        override fun onFailed(message: String, error: Throwable?) {
            SwingUtilities.invokeLater {
                setRunning(false)
                handle = null
                progress.value = 0
                statusLabel.text = "Scan failed"
                log.append(LogLevel.ERROR, message)
                Dialogs.error(this@ScanPanel, "Scan failed", message)
            }
        }
    }

    private fun setRunning(value: Boolean) {
        running = value
        runButton.isEnabled = !value && scopeModel.selectedExchanges().isNotEmpty() && chosenSkills().isNotEmpty()
        stopButton.isEnabled = value
        refreshButton.isEnabled = !value
        sourceCombo.isEnabled = !value
        runButton.text = if (value) "Running…" else "Run scan"
        if (!value) updateSummary()
    }

    private fun setLoading(value: Boolean) {
        refreshButton.isEnabled = !value
        refreshButton.text = if (value) "Loading…" else "Refresh"
        sourceCombo.isEnabled = !value
    }

    private fun isLoading(): Boolean = refreshButton.text == "Loading…"

    private fun styleCombo(combo: JComboBox<*>) {
        SectivUi.styleCombo(combo, theme)
    }

    private fun styleCheck(check: JCheckBox) {
        SectivUi.styleCheck(check, theme)
    }

    private fun formatChars(chars: Int): String = when {
        chars < 1024 -> "$chars chars"
        chars < 1024 * 1024 -> String.format("%.1f KB", chars / 1024.0)
        else -> String.format("%.1f MB", chars / (1024.0 * 1024.0))
    }

    private fun rootMessage(error: Throwable): String {
        var current: Throwable = error
        while (current.cause != null && current.cause !== current) current = current.cause!!
        return current.message ?: current.javaClass.simpleName
    }

    private fun isStaticAsset(path: String): Boolean {
        val segment = path.substringBefore('?').substringBefore('#').trimEnd('/').substringAfterLast('/')
        val dot = segment.lastIndexOf('.')
        if (dot <= 0 || dot == segment.length - 1) return false
        return segment.substring(dot + 1).lowercase() in STATIC_EXTENSIONS
    }

    override fun close() {
        handle?.cancel()
    }

    private class SkillRenderer(private val theme: SectivTheme) : ListCellRenderer<Skill> {
        override fun getListCellRendererComponent(
            list: JList<out Skill>?,
            value: Skill?,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean
        ): Component {
            val text = if (value == null) "No skills" else "${value.name}  ·  ${value.category}"
            val component = JLabel(text)
            component.isOpaque = true
            component.font = theme.small
            component.border = EmptyBorder(4, 8, 4, 8)
            component.background = if (isSelected) theme.tableSelection else theme.surfaceAlt
            component.foreground = theme.text
            return component
        }
    }

    companion object {
        // Static assets are dropped by the "Remove static files" filter. JavaScript
        // (and JSON/XML APIs) are deliberately kept because they are usually part of
        // the application logic and carry security-relevant behaviour.
        private val STATIC_EXTENSIONS = setOf(
            "png", "jpg", "jpeg", "gif", "ico", "svg", "webp", "bmp", "tif", "tiff",
            "css", "woff", "woff2", "ttf", "otf", "eot",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "md", "rtf",
            "mp3", "mp4", "wav", "avi", "mov", "webm", "mpeg", "mpg",
            "zip", "tar", "gz", "rar", "7z", "map"
        )
    }
}
