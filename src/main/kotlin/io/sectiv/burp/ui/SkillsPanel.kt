package io.sectiv.burp.ui

import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Skill
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.io.File
import java.nio.file.Files
import java.util.UUID
import javax.swing.BorderFactory
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.filechooser.FileNameExtensionFilter

class SkillsPanel(
    private val store: SectivStore,
    private val theme: SectivTheme
) : JPanel(BorderLayout()) {

    private val listModel = DefaultListModel<Skill>()
    private val list = JList(listModel)
    private val searchField = PlaceholderTextField(theme, "Search skills")

    private val nameField = textField()
    private val categoryField = textField()
    private val descriptionField = textField()
    private val instructionsArea = JTextArea().apply {
        font = theme.monoSmall
        background = theme.codeBackground
        foreground = Color(0xD9, 0xE2, 0xF2)
        caretColor = Color(0xD9, 0xE2, 0xF2)
        lineWrap = true
        wrapStyleWord = true
        border = EmptyBorder(10, 12, 10, 12)
        tabSize = 2
    }
    private val enabledCheck = JCheckBox("Enabled")
    private val builtInLabel = JLabel()
    private val dirtyLabel = JLabel("Unsaved changes")
    private val saveButton = PrimaryButton("Save skill", theme)
    private val revertButton = ghostButton("Revert", theme)

    private val newButton = ghostButton("New", theme)
    private val duplicateButton = ghostButton("Duplicate", theme)
    private val deleteButton = dangerButton("Delete", theme)
    private val importButton = ghostButton("Import .md", theme)
    private val exportButton = ghostButton("Export .md", theme)
    private val resetButton = ghostButton("Reset built-ins", theme)

    private var currentId: String? = null
    private var currentBuiltIn = false
    private var currentCreatedAt = System.currentTimeMillis()
    private var dirty = false
    private var loadingEditor = false
    private var suppressSelection = false
    private var skillsCache: List<Skill> = emptyList()
    private var allSkills: List<Skill> = emptyList()

    init {
        isOpaque = false
        background = theme.background
        border = EmptyBorder(16, 22, 16, 22)

        val headActions = JPanel(FlowLayout(FlowLayout.RIGHT, 7, 0)).apply {
            isOpaque = false
            add(importButton)
            add(newButton)
        }
        val pageHeader = PageHeader(
            theme,
            "Prompt library",
            "Skills",
            "Reusable review goals that shape the AI prompt. Edit, duplicate or import your own.",
            headActions
        )
        add(pageHeader, BorderLayout.NORTH)

        val listCard = buildListPanel().apply { preferredSize = Dimension(310, 320) }
        add(JPanel(BorderLayout(14, 0)).apply {
            isOpaque = false
            add(listCard, BorderLayout.WEST)
            add(buildEditorPanel(), BorderLayout.CENTER)
        }, BorderLayout.CENTER)

        wireEvents()
        refreshList(selectFirst = true)
        if (currentId == null && listModel.size > 0) {
            list.selectedIndex = 0
        }
        store.onChange {
            SwingUtilities.invokeLater {
                val skills = store.state().skills
                if (skills != skillsCache) refreshList(selectFirst = false)
            }
        }
        SwingUtilities.invokeLater {
            if (currentId == null && listModel.size > 0) list.selectedIndex = 0
        }
    }

    private fun buildListPanel(): JPanel {
        val card = Card(theme)
        card.layout = BorderLayout(0, 8)

        val search = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(JLabel("Library").apply {
                font = SectivFonts.semibold(13f)
                foreground = theme.text
            }, BorderLayout.WEST)
            add(JLabel("10 goals").apply {
                font = theme.monoSmall
                foreground = theme.faint
                horizontalAlignment = javax.swing.SwingConstants.RIGHT
            }, BorderLayout.EAST)
        }
        SectivUi.styleCheck(enabledCheck, theme)
        SectivUi.styleField(searchField, theme, padding = java.awt.Insets(6, 9, 6, 9), size = 11f)
        searchField.toolTipText = "Search skills"

        list.apply {
            font = theme.base
            background = theme.surface
            foreground = theme.textSoft
            selectionBackground = theme.tableSelection
            selectionForeground = theme.text
            selectionMode = ListSelectionModel.SINGLE_SELECTION
            cellRenderer = SkillListRenderer(theme)
            fixedCellHeight = 53
            border = EmptyBorder(2, 3, 2, 3)
        }
        list.addComponentListener(object : java.awt.event.ComponentAdapter() {
            override fun componentResized(e: java.awt.event.ComponentEvent) {
                val width = (list.width - 4).coerceAtLeast(220)
                if (list.fixedCellWidth != width) list.fixedCellWidth = width
            }
        })

        val buttons = JPanel().apply {
            isOpaque = false
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
            add(row(duplicateButton, deleteButton))
            add(javax.swing.Box.createVerticalStrut(4))
            add(row(exportButton, resetButton))
        }
        val top = JPanel().apply {
            isOpaque = false
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
            add(search)
            add(javax.swing.Box.createVerticalStrut(8))
            add(searchField)
        }
        card.add(top, BorderLayout.NORTH)
        card.add(JScrollPane(list).apply {
            border = RoundedBorder(theme.surface, theme.borderSoft, 9)
            viewport.background = theme.surface
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            themeScrollBars(this, theme)
        }, BorderLayout.CENTER)
        card.add(buttons, BorderLayout.SOUTH)
        return card
    }

    private fun buildEditorPanel(): JPanel {
        val card = Card(theme)
        card.layout = BorderLayout(0, 10)

        builtInLabel.font = theme.badge
        builtInLabel.foreground = theme.accent
        SectivUi.styleCheck(enabledCheck, theme)
        dirtyLabel.font = theme.small
        dirtyLabel.foreground = theme.warning
        dirtyLabel.isVisible = false
        exportButton.isEnabled = false

        val header = JPanel(BorderLayout()).apply {
            isOpaque = false
            val left = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
                isOpaque = false
                add(JLabel("Skill editor").apply { font = SectivFonts.semibold(13f); foreground = theme.text })
                add(builtInLabel)
            }
            val right = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0)).apply {
                isOpaque = false
                add(dirtyLabel)
                add(enabledCheck)
            }
            add(left, BorderLayout.WEST)
            add(right, BorderLayout.EAST)
        }

        val form = JPanel(GridBagLayout()).apply {
            isOpaque = false
        }
        val c = GridBagConstraints().apply {
            gridx = 0
            gridy = 0
            weightx = 0.0
            weighty = 0.0
            fill = GridBagConstraints.HORIZONTAL
            insets = Insets(0, 0, 8, 10)
            anchor = GridBagConstraints.NORTHWEST
        }
        form.add(fieldLabel("Name"), c)
        c.gridy = 1
        c.weightx = 1.0
        c.gridwidth = 1
        form.add(nameField, c)
        c.gridx = 1
        c.weightx = 0.0
        c.gridy = 0
        form.add(fieldLabel("Category"), c)
        c.gridy = 1
        c.weightx = 1.0
        form.add(categoryField, c)
        c.gridx = 0
        c.gridy = 2
        c.weightx = 0.0
        c.gridwidth = 2
        form.add(fieldLabel("Description (show in the goal picker)"), c)
        c.gridy = 3
        c.weightx = 1.0
        form.add(descriptionField, c)
        c.gridy = 4
        c.weightx = 0.0
        c.gridx = 0
        c.gridwidth = 2
        form.add(fieldLabel("Review instructions"), c)
        c.gridy = 5
        form.add(
            JLabel("A standard output format (description, steps to reproduce, impact, PoC, CWE/CVE) is appended automatically at review time and is not shown here.").apply {
                font = theme.tiny
                foreground = theme.faint
            },
            c
        )

        val layout = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(form, BorderLayout.NORTH)
            add(JScrollPane(instructionsArea).apply {
                border = RoundedBorder(theme.codeBackground, theme.border, 9)
                viewport.background = theme.codeBackground
                themeScrollBars(this, theme)
            }, BorderLayout.CENTER)
        }

        val footer = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(JLabel("Built-in prompts can be edited. Reset restores the originals.").apply {
                font = theme.tiny
                foreground = theme.faint
            }, BorderLayout.WEST)
            add(JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
                isOpaque = false
                add(revertButton)
                add(saveButton)
            }, BorderLayout.EAST)
        }

        card.add(header, BorderLayout.NORTH)
        card.add(layout, BorderLayout.CENTER)
        card.add(footer, BorderLayout.SOUTH)
        return card
    }

    private fun wireEvents() {
        list.addListSelectionListener {
            if (it.valueIsAdjusting || suppressSelection) return@addListSelectionListener
            val selected = list.selectedValue ?: return@addListSelectionListener
            if (selected.id == currentId) return@addListSelectionListener
            if (!confirmDiscard()) {
                restoreSelection()
                return@addListSelectionListener
            }
            loadEditor(selected)
        }

        searchField.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = rebuildFilteredList()
            override fun removeUpdate(e: DocumentEvent) = rebuildFilteredList()
            override fun changedUpdate(e: DocumentEvent) = rebuildFilteredList()
        })

        newButton.addActionListener {
            if (!confirmDiscard()) return@addActionListener
            val skill = Skill(
                id = UUID.randomUUID().toString(),
                name = "New skill",
                category = "Custom",
                description = "",
                instructions = DEFAULT_INSTRUCTIONS,
                builtIn = false
            )
            store.upsertSkill(skill)
            refreshList(selectFirst = false)
            selectById(skill.id)
            nameField.requestFocusInWindow()
            nameField.selectAll()
        }
        duplicateButton.addActionListener {
            val source = currentSkill() ?: return@addActionListener
            if (!confirmDiscard()) return@addActionListener
            val copy = source.copy(
                id = UUID.randomUUID().toString(),
                name = source.name + " (copy)",
                builtIn = false,
                createdAt = System.currentTimeMillis()
            )
            store.upsertSkill(copy)
            refreshList(selectFirst = false)
            selectById(copy.id)
        }
        deleteButton.addActionListener {
            val skill = currentSkill() ?: return@addActionListener
            if (!Dialogs.confirm(this, "Delete skill", "Delete \"${skill.name}\"? Built-in skills can be restored with Reset built-ins.")) return@addActionListener
            store.deleteSkill(skill.id)
            currentId = null
            dirty = false
            refreshList(selectFirst = true)
            currentId?.let { selectById(it) }
            if (listModel.size == 0) clearEditor()
        }
        saveButton.addActionListener { saveCurrent() }
        revertButton.addActionListener { currentSkill()?.let { loadEditor(it) } }
        resetButton.addActionListener {
            if (!Dialogs.confirm(this, "Reset built-in skills", "Restore the original prompt text for all built-in skills? Your custom skills are kept.")) return@addActionListener
            store.resetBuiltInSkills()
            refreshList(selectFirst = false)
            currentId?.let { selectById(it) }
        }
        importButton.addActionListener { importSkill() }
        exportButton.addActionListener { exportSkill() }

        val dirtyListener = object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = markDirty()
            override fun removeUpdate(e: DocumentEvent) = markDirty()
            override fun changedUpdate(e: DocumentEvent) = markDirty()
        }
        nameField.document.addDocumentListener(dirtyListener)
        categoryField.document.addDocumentListener(dirtyListener)
        descriptionField.document.addDocumentListener(dirtyListener)
        instructionsArea.document.addDocumentListener(dirtyListener)
        enabledCheck.addActionListener { markDirty() }
    }

    private fun refreshList(selectFirst: Boolean) {
        allSkills = store.state().skills
        skillsCache = allSkills
        val previousId = currentId
        rebuildFilteredList()
        if (previousId != null) {
            val restored = selectById(previousId)
            if (!restored && selectFirst && listModel.size > 0) list.selectedIndex = 0
        } else if (selectFirst && listModel.size > 0) {
            list.selectedIndex = 0
        }
    }

    private fun rebuildFilteredList() {
        val query = searchField.text.trim().lowercase()
        val filtered = allSkills.filter { skill ->
            query.isEmpty() || listOf(skill.name, skill.category, skill.description)
                .joinToString(" ").lowercase().contains(query)
        }
        val selectedId = list.selectedValue?.id ?: currentId
        suppressSelection = true
        listModel.clear()
        filtered.forEach { listModel.addElement(it) }
        if (selectedId != null) {
            for (i in 0 until listModel.size()) {
                if (listModel.getElementAt(i).id == selectedId) {
                    list.selectedIndex = i
                    break
                }
            }
        }
        suppressSelection = false
    }

    private fun selectById(id: String): Boolean {
        for (i in 0 until listModel.size()) {
            if (listModel.getElementAt(i).id == id) {
                suppressSelection = true
                list.selectedIndex = i
                suppressSelection = false
                loadEditor(listModel.getElementAt(i))
                return true
            }
        }
        return false
    }

    private fun restoreSelection() {
        val id = currentId ?: return
        suppressSelection = true
        for (i in 0 until listModel.size()) {
            if (listModel.getElementAt(i).id == id) {
                list.selectedIndex = i
                break
            }
        }
        suppressSelection = false
    }

    private fun loadEditor(skill: Skill) {
        loadingEditor = true
        currentId = skill.id
        currentBuiltIn = skill.builtIn
        currentCreatedAt = skill.createdAt
        nameField.text = skill.name
        categoryField.text = skill.category
        descriptionField.text = skill.description
        instructionsArea.text = skill.instructions
        instructionsArea.caretPosition = 0
        enabledCheck.isSelected = skill.enabled
        builtInLabel.text = if (skill.builtIn) "BUILT-IN" else "CUSTOM"
        builtInLabel.foreground = if (skill.builtIn) theme.accent else theme.muted
        exportButton.isEnabled = true
        loadingEditor = false
        setDirty(false)
    }

    private fun clearEditor() {
        loadingEditor = true
        currentId = null
        nameField.text = ""
        categoryField.text = ""
        descriptionField.text = ""
        instructionsArea.text = ""
        enabledCheck.isSelected = false
        builtInLabel.text = ""
        loadingEditor = false
        setDirty(false)
        exportButton.isEnabled = false
    }

    private fun markDirty() {
        if (loadingEditor) return
        setDirty(true)
    }

    private fun setDirty(value: Boolean) {
        dirty = value
        dirtyLabel.isVisible = value
        saveButton.text = if (value) "Save changes" else "Save skill"
        if (currentId == null) dirtyLabel.isVisible = false
    }

    private fun confirmDiscard(): Boolean {
        if (!dirty) return true
        return Dialogs.confirm(
            this,
            "Discard changes?",
            "You have unsaved changes to this skill. Discard them?"
        )
    }

    private fun currentSkill(): Skill? {
        val id = currentId ?: return null
        return store.state().skills.firstOrNull { it.id == id }
    }

    private fun collectEditor(): Skill? {
        val name = nameField.text.trim()
        if (name.isBlank()) {
            Dialogs.error(this, "Skill needs a name", "Enter a short name for this review goal.")
            return null
        }
        val instructions = instructionsArea.text.trim()
        if (instructions.isBlank()) {
            Dialogs.error(this, "Skill needs instructions", "Describe what the AI should look for in captured traffic.")
            return null
        }
        return Skill(
            id = currentId ?: UUID.randomUUID().toString(),
            name = name,
            category = categoryField.text.trim().ifBlank { "Custom" },
            description = descriptionField.text.trim(),
            instructions = instructions,
            enabled = enabledCheck.isSelected,
            builtIn = currentBuiltIn,
            createdAt = currentCreatedAt
        )
    }

    private fun saveCurrent() {
        val skill = collectEditor() ?: return
        store.upsertSkill(skill)
        currentId = skill.id
        currentBuiltIn = skill.builtIn
        setDirty(false)
        refreshList(selectFirst = false)
        selectById(skill.id)
    }

    private fun importSkill() {
        if (!confirmDiscard()) return
        val chooser = JFileChooser().apply {
            dialogTitle = "Import skill"
            fileFilter = FileNameExtensionFilter("Markdown (*.md, *.txt)", "md", "txt")
        }
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return
        val file = chooser.selectedFile
        try {
            val skill = parseMarkdown(file.name, Files.readString(file.toPath()))
            store.upsertSkill(skill)
            refreshList(selectFirst = false)
            selectById(skill.id)
            Dialogs.info(this, "Skill imported", "Imported \"${skill.name}\".")
        } catch (e: Exception) {
            Dialogs.error(this, "Import failed", e.message ?: e.javaClass.simpleName)
        }
    }

    private fun exportSkill() {
        val skill = collectEditor() ?: return
        val chooser = JFileChooser().apply {
            dialogTitle = "Export skill"
            selectedFile = File(skill.name.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-') + ".md")
            fileFilter = FileNameExtensionFilter("Markdown (*.md)", "md")
        }
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        var file = chooser.selectedFile
        if (!file.name.lowercase().endsWith(".md")) file = File(file.parentFile, file.name + ".md")
        try {
            val frontmatter = buildString {
                appendLine("---")
                appendLine("name: ${skill.name}")
                appendLine("category: ${skill.category}")
                appendLine("description: ${skill.description.replace("\n", " ")}")
                appendLine("enabled: ${skill.enabled}")
                appendLine("---")
                appendLine()
                append(skill.instructions)
            }
            Files.writeString(file.toPath(), frontmatter)
            Dialogs.info(this, "Skill exported", "Saved to:\n${file.absolutePath}")
        } catch (e: Exception) {
            Dialogs.error(this, "Export failed", e.message ?: e.javaClass.simpleName)
        }
    }

    private fun parseMarkdown(fileName: String, content: String): Skill {
        var name = fileName.substringBeforeLast('.').replace('-', ' ').replace('_', ' ').trim()
        var category = "Imported"
        var description = ""
        var body = content.trim()

        if (body.startsWith("---")) {
            val end = body.indexOf("\n---", 3)
            if (end > 0) {
                val front = body.substring(3, end).trim()
                body = body.substring(end + 4).trim()
                for (line in front.lineSequence()) {
                    val idx = line.indexOf(':')
                    if (idx <= 0) continue
                    val key = line.substring(0, idx).trim().lowercase()
                    val value = line.substring(idx + 1).trim()
                    when (key) {
                        "name" -> if (value.isNotBlank()) name = value
                        "category" -> if (value.isNotBlank()) category = value
                        "description" -> description = value
                    }
                }
            }
        }
        if (description.isBlank()) {
            description = body.lineSequence()
                .map { it.trim() }
                .firstOrNull { it.isNotBlank() && !it.startsWith("#") }
                ?.removePrefix("-")
                ?.trim()
                ?.take(200)
                .orEmpty()
        }
        return Skill(
            id = UUID.randomUUID().toString(),
            name = name.ifBlank { "Imported skill" },
            category = category,
            description = description,
            instructions = body,
            builtIn = false
        )
    }

    private fun textField(): JTextField = JTextField().apply {
        SectivUi.styleField(this, theme, fill = theme.backgroundDeep, padding = java.awt.Insets(6, 9, 6, 9), size = 11f)
        preferredSize = Dimension(300, 30)
    }

    private fun fieldLabel(text: String): JLabel = JLabel(text).apply {
        font = theme.small
        foreground = theme.muted
    }

    private fun row(vararg components: Component): JPanel =
        JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            isOpaque = false
            components.forEach { add(it) }
        }

    private class SkillListRenderer(private val theme: SectivTheme) : javax.swing.ListCellRenderer<Skill> {
        override fun getListCellRendererComponent(
            list: JList<out Skill>?,
            value: Skill?,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean
        ): Component {
            val panel = JPanel(BorderLayout())
            panel.isOpaque = true
            panel.background = if (isSelected) theme.surfaceRaised else theme.surface
            panel.border = EmptyBorder(7, 11, 7, 10)
            if (value == null) return panel

            val text = JPanel().apply {
                isOpaque = false
                layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
                add(JLabel(value.name).apply {
                    font = SectivFonts.medium(11.5f)
                    foreground = if (value.enabled) theme.textSoft else theme.faint
                })
                add(JLabel(value.category + if (value.enabled) "" else " · disabled").apply {
                    font = theme.monoSmall
                    foreground = theme.faint
                })
            }
            panel.add(text, BorderLayout.CENTER)

            val dot = object : JComponent() {
                init {
                    preferredSize = Dimension(8, 8)
                }
                override fun paintComponent(g: Graphics) {
                    val g2 = g.create() as Graphics2D
                    try {
                        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                        g2.color = if (value.enabled) theme.success else theme.faint
                        g2.fillOval(1, 3, 4, 4)
                    } finally {
                        g2.dispose()
                    }
                }
            }
            panel.add(dot, BorderLayout.EAST)
            panel.toolTipText = if (value.description.isBlank()) value.name else "${value.name} — ${value.description}"
            return panel
        }
    }

    fun selectSkill(id: String?) {
        if (id == null) return
        if (dirty && !confirmDiscard()) return
        refreshList(selectFirst = false)
        if (!selectById(id) && listModel.size > 0) list.selectedIndex = 0
    }

    companion object {
        private val DEFAULT_INSTRUCTIONS = """
            Review the captured traffic for the security issue described by this skill.

            Focus on:
            - The exact request parameters, headers or flows that matter.
            - The response evidence that confirms the issue.
            - Any identity or role differences visible in the traffic.

            Only report findings supported by the captures. If the evidence is suggestive but not conclusive, mark the finding tentative and explain what would confirm it.
        """.trimIndent()
    }
}
