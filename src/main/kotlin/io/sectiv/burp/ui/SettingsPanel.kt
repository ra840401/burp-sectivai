package io.sectiv.burp.ui

import io.sectiv.burp.ai.LlmClient
import io.sectiv.burp.core.Json
import io.sectiv.burp.core.ProviderConfig
import io.sectiv.burp.core.ProviderKind
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Settings
import io.sectiv.burp.core.Text
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SpinnerNumberModel
import javax.swing.SwingUtilities
import javax.swing.SwingWorker
import javax.swing.border.EmptyBorder
import javax.swing.event.ChangeListener
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class SettingsPanel(
    private val store: SectivStore,
    private val theme: SectivTheme
) : JPanel(BorderLayout()) {

    private var settings: Settings = store.state().settings
    private var loading = false
    private var dirty = false
    private var suppressProviderEvent = false
    private var lastProviderId: String? = null

    private val providerCombo = JComboBox<ProviderConfig>()
    private val providerHint = JLabel()
    private val docsHolder = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply { isOpaque = false }

    private val baseUrlField = textField()
    private val modelField = textField()
    private val apiKeyField = JPasswordField(32).apply {
        echoChar = '•'
        SectivUi.styleField(this, theme, fill = theme.backgroundDeep, padding = java.awt.Insets(6, 9, 6, 9), size = 11f)
        preferredSize = Dimension(320, 30)
    }
    private val showKeyCheck = JCheckBox("Show")
    private val maxTokensSpinner = spinner(8192, 1, 200_000, 512)
    private val timeoutSpinner = spinner(180, 15, 900, 15)
    private val tokenFieldCombo = JComboBox(arrayOf("max_tokens", "max_completion_tokens"))
    private val temperatureCheck = JCheckBox("Send temperature")
    private val temperatureSpinner = JSpinner(SpinnerNumberModel(0.1, 0.0, 2.0, 0.1))
    private val headersArea = JTextArea(3, 30).apply {
        isOpaque = false
        background = theme.codeBackground
        foreground = theme.codeText
        caretColor = theme.codeText
        selectionColor = theme.accentSoft
        selectedTextColor = theme.text
        font = theme.monoSmall
        border = EmptyBorder(7, 9, 7, 9)
    }
    private val bodyArea = JTextArea(3, 30).apply {
        isOpaque = false
        background = theme.codeBackground
        foreground = theme.codeText
        caretColor = theme.codeText
        selectionColor = theme.accentSoft
        selectedTextColor = theme.text
        font = theme.monoSmall
        border = EmptyBorder(7, 9, 7, 9)
    }
    private val testButton = ghostButton("Test connection", theme)
    private val testStatus = JLabel()

    private val chunkSpinner = spinner(42_000, 8_000, 200_000, 2_000)
    private val findingsSpinner = spinner(8, 1, 25, 1)
    private val responseSpinner = spinner(7_000, 500, 30_000, 500)
    private val maskSecretsCheck = JCheckBox("Mask cookies and tokens before sending prompts")
    private val autoScopeCheck = JCheckBox("Auto-select in-scope items when history loads")
    private val stateChangingCheck = JCheckBox("Allow POST/PUT/PATCH/DELETE in identity-swap checks")
    private val maxSwapSpinner = spinner(20, 1, 200, 1)
    private val delaySpinner = spinner(300, 0, 5_000, 50)

    private val footerStatus = JLabel("Settings loaded")
    private val saveButton = PrimaryButton("Save settings", theme)
    private val revertButton = ghostButton("Revert", theme)
    private val storageLabel = JLabel(store.storagePath)
    private val clearFindingsButton = dangerButton("Clear all findings", theme)
    private val resetSettingsButton = dangerButton("Reset settings", theme)

    init {
        isOpaque = false
        background = theme.background
        border = EmptyBorder(16, 22, 16, 22)

        val actions = JPanel(FlowLayout(FlowLayout.RIGHT, 7, 0)).apply {
            isOpaque = false
            add(revertButton)
            add(saveButton)
        }
        val pageHeader = PageHeader(
            theme,
            "Configuration",
            "Settings",
            "Provider, prompt budget and active-check behaviour.",
            actions
        )
        add(pageHeader, BorderLayout.NORTH)

        val rightColumn = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = LEFT_ALIGNMENT
            add(fullWidth(buildScanCard()))
            add(Box.createVerticalStrut(10))
            add(fullWidth(buildActiveCard()))
            add(Box.createVerticalStrut(10))
            add(fullWidth(buildDataCard()))
        }

        val columns = ScrollableColumn().apply {
            isOpaque = false
            layout = GridBagLayout()
            border = EmptyBorder(0, 0, 0, 4)
            val c = GridBagConstraints().apply {
                gridx = 0
                gridy = 0
                weightx = 0.63
                weighty = 0.0
                fill = GridBagConstraints.HORIZONTAL
                anchor = GridBagConstraints.NORTHWEST
                insets = Insets(0, 0, 0, 7)
            }
            add(fullWidth(buildProviderCard()), c)
            c.gridx = 1
            c.weightx = 0.37
            c.insets = Insets(0, 7, 0, 0)
            add(rightColumn, c)
        }

        val footer = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = EmptyBorder(8, 2, 0, 2)
            footerStatus.font = theme.small
            footerStatus.foreground = theme.muted
            add(footerStatus, BorderLayout.WEST)
            add(JLabel("State is stored locally at ~/.sectiv/state.json").apply {
                font = theme.tiny
                foreground = theme.faint
            }, BorderLayout.EAST)
        }

        add(JScrollPane(columns).apply {
            border = BorderFactory.createEmptyBorder()
            viewport.background = theme.background
            background = theme.background
            verticalScrollBar.unitIncrement = 18
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            themeScrollBars(this, theme)
        }, BorderLayout.CENTER)
        add(footer, BorderLayout.SOUTH)

        styleControls()
        wireEvents()
        loadProviders()
        loadSettings(settings)
    }

    private fun fullWidth(card: JPanel): JPanel =
        JPanel(BorderLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(card, BorderLayout.CENTER)
        }

    private fun buildProviderCard(): JPanel {
        val card = Card(theme, "AI provider")

        SectivUi.styleCombo(providerCombo, theme)
        providerCombo.preferredSize = Dimension(260, 32)
        providerCombo.renderer = object : javax.swing.DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                list: javax.swing.JList<*>?,
                value: Any?,
                index: Int,
                isSelected: Boolean,
                cellHasFocus: Boolean
            ): Component {
                val provider = value as? ProviderConfig
                val component = super.getListCellRendererComponent(
                    list, provider?.name ?: "", index, isSelected, cellHasFocus
                )
                component.font = theme.small
                component.background = if (isSelected) theme.surfaceRaised else theme.surfaceAlt
                component.foreground = theme.text
                return component
            }
        }

        val top = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(JLabel("Provider").apply { font = theme.small; foreground = theme.muted })
            add(providerCombo)
            providerHint.font = theme.tiny
            providerHint.foreground = theme.faint
            add(providerHint)
            add(docsHolder)
        }

        val form = JPanel(GridBagLayout()).apply { isOpaque = false }
        var row = 0
        addFormRow(form, row++, "Base URL", baseUrlField, "Full chat-completions endpoint. OpenAI-compatible providers usually end in /v1/chat/completions.")
        addFormRow(form, row++, "Model", modelField, "Exact model identifier, e.g. deepseek-chat, claude-sonnet-4-5, glm-4.6.")
        val keyRow = JPanel(BorderLayout(6, 0)).apply {
            isOpaque = false
            add(apiKeyField, BorderLayout.CENTER)
            add(showKeyCheck, BorderLayout.EAST)
        }
        addFormRow(form, row++, "API key", keyRow, "Stored locally in the state file with 0600 permissions where supported. Never sent anywhere except the provider.")
        val numbers = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(JLabel("Max output tokens").apply { font = theme.tiny; foreground = theme.muted })
            maxTokensSpinner.preferredSize = Dimension(96, 28)
            add(maxTokensSpinner)
            add(Box.createHorizontalStrut(8))
            add(JLabel("Timeout (s)").apply { font = theme.tiny; foreground = theme.muted })
            timeoutSpinner.preferredSize = Dimension(76, 28)
            add(timeoutSpinner)
        }
        addFormRow(form, row++, "Limits", numbers, null)
        val advanced = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(JLabel("Token field").apply { font = theme.tiny; foreground = theme.muted })
            tokenFieldCombo.preferredSize = Dimension(180, 28)
            add(tokenFieldCombo)
            add(Box.createHorizontalStrut(8))
            add(temperatureCheck)
            temperatureSpinner.preferredSize = Dimension(64, 28)
            add(temperatureSpinner)
        }
        addFormRow(form, row++, "Request shape", advanced, "OpenAI's newest models use max_completion_tokens. Reasoning models may reject temperature.")
        addFormRow(form, row++, "Extra headers", scrollArea(headersArea, 64), "One Name: value per line. Added to every provider request.")
        addFormRow(form, row++, "Extra body JSON", scrollArea(bodyArea, 64), "Optional JSON object merged into the request body. Advanced use only.")

        testStatus.font = theme.small
        testStatus.foreground = theme.muted
        val testRow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(testButton)
            add(testStatus)
        }

        val body = JPanel(BorderLayout(0, 10)).apply {
            isOpaque = false
            add(top, BorderLayout.NORTH)
            add(form, BorderLayout.CENTER)
            add(testRow, BorderLayout.SOUTH)
        }
        card.add(body, BorderLayout.CENTER)
        return card
    }

    private fun buildScanCard(): JPanel {
        val card = Card(theme, "Scan behavior")
        val body = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
        }

        val numbers = JPanel(FlowLayout(FlowLayout.LEFT, 16, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(namedField("Prompt chunk size (chars)", chunkSpinner))
            add(namedField("Max findings / chunk", findingsSpinner))
            add(namedField("Response chars / request", responseSpinner))
        }
        styleCheck(maskSecretsCheck)
        styleCheck(autoScopeCheck)
        maskSecretsCheck.alignmentX = LEFT_ALIGNMENT
        autoScopeCheck.alignmentX = LEFT_ALIGNMENT
        val note = help("Chunk size controls how much captured traffic goes into each AI call. Larger chunks mean fewer calls but a higher chance of hitting model context limits.")
        body.add(numbers)
        body.add(Box.createVerticalStrut(8))
        body.add(maskSecretsCheck)
        body.add(Box.createVerticalStrut(4))
        body.add(autoScopeCheck)
        body.add(Box.createVerticalStrut(8))
        body.add(note)
        card.add(body, BorderLayout.CENTER)
        return card
    }

    private fun buildActiveCard(): JPanel {
        val card = Card(theme, "Active identity checks")
        val body = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
        }

        styleCheck(stateChangingCheck)
        stateChangingCheck.alignmentX = LEFT_ALIGNMENT
        val numbers = JPanel(FlowLayout(FlowLayout.LEFT, 16, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(namedField("Max requests", maxSwapSpinner))
            add(namedField("Delay (ms)", delaySpinner))
        }
        val warning = help(
            "Identity-swap checks replay captured requests with User B's credentials. They only run when you tick the option on the Scan tab and confirm the request count. Keep state-changing methods off unless you understand the impact."
        )
        body.add(stateChangingCheck)
        body.add(Box.createVerticalStrut(8))
        body.add(numbers)
        body.add(Box.createVerticalStrut(8))
        body.add(warning)
        card.add(body, BorderLayout.CENTER)
        return card
    }

    private fun buildDataCard(): JPanel {
        val card = Card(theme, "Data")
        val body = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
        }

        storageLabel.font = theme.monoSmall
        storageLabel.foreground = theme.textSoft
        storageLabel.text = store.storagePath
        storageLabel.alignmentX = LEFT_ALIGNMENT
        val pathRow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(JLabel("State file").apply { font = theme.small; foreground = theme.muted })
            add(storageLabel)
            add(ghostButton("Copy path", theme).apply {
                addActionListener {
                    Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(store.storagePath), null)
                }
            })
        }
        val actions = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(clearFindingsButton)
            add(resetSettingsButton)
        }
        body.add(pathRow)
        body.add(Box.createVerticalStrut(8))
        body.add(help("Settings, skills, identity context and findings are stored together. The file is not encrypted, so use a dedicated API key and rotate it if the host is shared."))
        body.add(Box.createVerticalStrut(10))
        body.add(actions)
        card.add(body, BorderLayout.CENTER)
        return card
    }

    private fun wireEvents() {
        providerCombo.addActionListener {
            if (loading || suppressProviderEvent) return@addActionListener
            val selected = providerCombo.selectedItem as? ProviderConfig ?: return@addActionListener
            if (dirty) {
                if (!Dialogs.confirm(this, "Discard changes?", "Discard unsaved changes to the current provider?")) {
                    restoreProviderSelection()
                    return@addActionListener
                }
            }
            loadProvider(selected)
            setDirty(false)
        }

        showKeyCheck.addActionListener {
            apiKeyField.echoChar = if (showKeyCheck.isSelected) 0.toChar() else '•'
        }

        saveButton.addActionListener { saveAll() }
        revertButton.addActionListener { loadSettings(settings) }

        testButton.addActionListener { testConnection() }

        clearFindingsButton.addActionListener {
            val count = store.state().findings.size
            if (count == 0) {
                Dialogs.info(this, "Nothing to clear", "There are no findings to delete.")
                return@addActionListener
            }
            if (Dialogs.confirm(this, "Clear findings", "Delete all $count finding(s)? This cannot be undone.")) {
                store.clearFindings()
                footerStatus.text = "All findings cleared"
            }
        }
        resetSettingsButton.addActionListener {
            if (!Dialogs.confirm(this, "Reset settings", "Reset provider settings and scan options to their defaults? Skills and findings are kept.")) return@addActionListener
            val defaults = Settings().withMissingPresets()
            store.setSettings(defaults)
            settings = defaults
            rebuildProviderCombo()
            loadSettings(defaults)
            footerStatus.text = "Settings reset to defaults"
        }

        val dirtyListener = object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = markDirty()
            override fun removeUpdate(e: DocumentEvent) = markDirty()
            override fun changedUpdate(e: DocumentEvent) = markDirty()
        }
        baseUrlField.document.addDocumentListener(dirtyListener)
        modelField.document.addDocumentListener(dirtyListener)
        apiKeyField.document.addDocumentListener(dirtyListener)
        headersArea.document.addDocumentListener(dirtyListener)
        bodyArea.document.addDocumentListener(dirtyListener)

        val change = ChangeListener { markDirty() }
        maxTokensSpinner.addChangeListener(change)
        timeoutSpinner.addChangeListener(change)
        temperatureSpinner.addChangeListener(change)
        chunkSpinner.addChangeListener(change)
        findingsSpinner.addChangeListener(change)
        responseSpinner.addChangeListener(change)
        maxSwapSpinner.addChangeListener(change)
        delaySpinner.addChangeListener(change)

        maskSecretsCheck.addActionListener { markDirty() }
        autoScopeCheck.addActionListener { markDirty() }
        stateChangingCheck.addActionListener { markDirty() }
        temperatureCheck.addActionListener {
            temperatureSpinner.isEnabled = temperatureCheck.isSelected
            markDirty()
        }
        tokenFieldCombo.addActionListener { markDirty() }
    }

    private fun loadProviders() {
        settings = store.state().settings
        suppressProviderEvent = true
        providerCombo.removeAllItems()
        settings.providers.forEach { providerCombo.addItem(it) }
        val active = settings.providers.firstOrNull { it.id == settings.activeProviderId } ?: settings.providers.first()
        providerCombo.selectedItem = active
        suppressProviderEvent = false
        loadProvider(active)
    }

    private fun rebuildProviderCombo() {
        suppressProviderEvent = true
        providerCombo.removeAllItems()
        settings.providers.forEach { providerCombo.addItem(it) }
        val active = settings.providers.firstOrNull { it.id == settings.activeProviderId } ?: settings.providers.first()
        providerCombo.selectedItem = active
        suppressProviderEvent = false
        refreshDocs(active)
    }

    private fun restoreProviderSelection() {
        suppressProviderEvent = true
        val target = settings.providers.firstOrNull { it.id == lastProviderId }
            ?: settings.providers.first()
        providerCombo.selectedItem = target
        suppressProviderEvent = false
    }

    private fun loadProvider(provider: ProviderConfig) {
        loading = true
        settings = settings.copy(activeProviderId = provider.id)
        baseUrlField.text = provider.baseUrl
        modelField.text = provider.model
        apiKeyField.text = provider.apiKey
        maxTokensSpinner.value = provider.maxTokens
        timeoutSpinner.value = provider.timeoutSeconds
        tokenFieldCombo.selectedItem = provider.maxTokensField.ifBlank { "max_tokens" }
        val canTemperature = provider.temperature != null
        temperatureCheck.isSelected = canTemperature
        temperatureSpinner.isEnabled = canTemperature
        temperatureSpinner.value = provider.temperature ?: 0.1
        headersArea.text = provider.extraHeaders.entries.joinToString("\n") { "${it.key}: ${it.value}" }
        bodyArea.text = provider.extraBodyJson
        providerHint.text = when (provider.kind) {
            ProviderKind.ANTHROPIC -> "Anthropic Messages API"
            ProviderKind.OPENAI -> "OpenAI-compatible chat completions"
        }
        refreshDocs(provider)
        lastProviderId = provider.id
        testStatus.text = ""
        testStatus.foreground = theme.muted
        loading = false
    }

    private fun refreshDocs(provider: ProviderConfig) {
        docsHolder.removeAll()
        docsHolder.add(
            if (provider.docsUrl.isBlank()) {
                JLabel(if (provider.requiresApiKey) "" else "No key required").apply {
                    font = theme.tiny
                    foreground = theme.faint
                }
            } else {
                LinkLabel("Get an API key", provider.docsUrl, theme)
            }
        )
        docsHolder.revalidate()
        docsHolder.repaint()
    }

    private fun loadSettings(value: Settings) {
        settings = value
        loading = true
        chunkSpinner.value = value.chunkChars
        findingsSpinner.value = value.maxFindingsPerChunk
        responseSpinner.value = value.maxResponseChars
        maskSecretsCheck.isSelected = value.maskSecrets
        autoScopeCheck.isSelected = value.autoSelectInScope
        stateChangingCheck.isSelected = value.allowStateChangingChecks
        maxSwapSpinner.value = value.maxSwapRequests
        delaySpinner.value = value.requestDelayMs
        val provider = value.providers.firstOrNull { it.id == value.activeProviderId } ?: value.providers.first()
        loadProvider(provider)
        loading = false
        setDirty(false)
        footerStatus.text = "Settings loaded"
    }

    private fun saveAll() {
        val provider = collectProvider() ?: return
        val newSettings = Settings(
            activeProviderId = provider.id,
            providers = settings.providers.map { if (it.id == provider.id) provider else it },
            chunkChars = (chunkSpinner.value as Number).toInt(),
            maxFindingsPerChunk = (findingsSpinner.value as Number).toInt(),
            maxResponseChars = (responseSpinner.value as Number).toInt(),
            maskSecrets = maskSecretsCheck.isSelected,
            allowStateChangingChecks = stateChangingCheck.isSelected,
            maxSwapRequests = (maxSwapSpinner.value as Number).toInt(),
            requestDelayMs = (delaySpinner.value as Number).toInt(),
            autoSelectInScope = autoScopeCheck.isSelected
        )
        store.setSettings(newSettings)
        settings = newSettings
        setDirty(false)
        footerStatus.text = "Saved · ${provider.name} is active"
        footerStatus.foreground = theme.success
        rebuildProviderCombo()
        loadProvider(provider)
        setDirty(false)
        testStatus.text = ""
    }

    private fun collectProvider(): ProviderConfig? {
        val current = providerCombo.selectedItem as? ProviderConfig ?: return null
        val baseUrl = baseUrlField.text.trim()
        val model = modelField.text.trim()
        if (baseUrl.isBlank() || (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://"))) {
            Dialogs.error(this, "Invalid base URL", "Enter the full endpoint, starting with https:// or http://.")
            return null
        }
        if (model.isBlank()) {
            Dialogs.error(this, "Model required", "Enter the model name exactly as the provider expects it.")
            return null
        }
        val extraHeaders = mutableMapOf<String, String>()
        for ((index, line) in headersArea.text.lineSequence().withIndex()) {
            val trimmed = line.trim()
            if (trimmed.isBlank() || trimmed.startsWith("#")) continue
            val colon = trimmed.indexOf(':')
            if (colon <= 0) {
                Dialogs.error(this, "Invalid header", "Line ${index + 1} is not in \"Name: value\" format.")
                return null
            }
            extraHeaders[trimmed.substring(0, colon).trim()] = trimmed.substring(colon + 1).trim()
        }
        val extraBody = bodyArea.text.trim()
        if (extraBody.isNotEmpty()) {
            try {
                val node = Json.parseTree(extraBody)
                if (!node.isObject) {
                    Dialogs.error(this, "Invalid extra body", "Extra body JSON must be a JSON object.")
                    return null
                }
            } catch (e: Exception) {
                Dialogs.error(this, "Invalid extra body", "Could not parse JSON: ${e.message}")
                return null
            }
        }
        return current.copy(
            baseUrl = baseUrl,
            model = model,
            apiKey = String(apiKeyField.password).trim(),
            maxTokens = (maxTokensSpinner.value as Number).toInt(),
            timeoutSeconds = (timeoutSpinner.value as Number).toInt(),
            maxTokensField = (tokenFieldCombo.selectedItem as? String) ?: "max_tokens",
            temperature = if (temperatureCheck.isSelected) (temperatureSpinner.value as Number).toDouble() else null,
            extraHeaders = extraHeaders,
            extraBodyJson = extraBody
        )
    }

    private fun testConnection() {
        val provider = collectProvider() ?: return
        if (provider.requiresApiKey && provider.apiKey.isBlank()) {
            Dialogs.error(this, "API key required", "Add an API key before testing ${provider.name}.")
            return
        }
        testButton.isEnabled = false
        testStatus.text = "Testing…"
        testStatus.foreground = theme.muted
        object : SwingWorker<String, Void>() {
            override fun doInBackground(): String = LlmClient().ping(provider)
            override fun done() {
                testButton.isEnabled = true
                try {
                    val reply = get()
                    testStatus.text = "Connected · ${reply.take(80)}"
                    testStatus.foreground = theme.success
                } catch (e: Exception) {
                    val cause = e.cause ?: e
                    testStatus.text = "Failed · ${Text.safeMessage(cause.message, 300)}"
                    testStatus.foreground = theme.danger
                }
            }
        }.execute()
    }

    private fun markDirty() {
        if (loading) return
        setDirty(true)
    }

    private fun setDirty(value: Boolean) {
        dirty = value
        footerStatus.text = if (value) "Unsaved changes" else "Settings loaded"
        footerStatus.foreground = if (value) theme.warning else theme.muted
    }

    private fun addFormRow(
        form: JPanel,
        row: Int,
        label: String,
        component: Component,
        helpText: String?
    ) {
        val c = GridBagConstraints().apply {
            gridx = 0
            gridy = row
            weightx = 0.0
            fill = GridBagConstraints.HORIZONTAL
            insets = Insets(5, 0, 6, 12)
            anchor = GridBagConstraints.NORTHWEST
        }
        form.add(JLabel(label).apply {
            font = theme.small
            foreground = theme.muted
        }, c)

        val field = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(component)
            if (helpText != null) {
                add(Box.createVerticalStrut(4))
                add(htmlLabel(helpText, theme.tiny, theme.faint, 500))
            }
        }
        c.gridx = 1
        c.weightx = 1.0
        form.add(field, c)
    }

    private fun namedField(text: String, spinner: JSpinner): JPanel =
        JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            isOpaque = false
            add(JLabel(text).apply { font = theme.tiny; foreground = theme.muted })
            spinner.preferredSize = Dimension(92, 28)
            add(spinner)
        }

    private fun help(text: String): JComponent = htmlLabel(text, theme.tiny, theme.faint, 250).apply {
        alignmentX = LEFT_ALIGNMENT
    }

    private fun textField(): JTextField = JTextField().apply {
        SectivUi.styleField(this, theme, fill = theme.backgroundDeep, padding = java.awt.Insets(6, 9, 6, 9), size = 11f)
        preferredSize = Dimension(360, 30)
    }

    private fun spinner(value: Int, min: Int, max: Int, step: Int): JSpinner =
        JSpinner(SpinnerNumberModel(value, min, max, step)).apply {
            font = theme.small
            editor = JSpinner.NumberEditor(this, "0")
            (editor as JSpinner.DefaultEditor).textField.apply {
                SectivUi.styleField(this, theme, fill = theme.backgroundDeep, padding = java.awt.Insets(4, 6, 4, 6), size = 10.5f)
            }
            isOpaque = false
            border = RoundedBorder(theme.backgroundDeep, theme.border, 8)
        }

    private fun scrollArea(area: JTextArea, height: Int): JScrollPane =
        JScrollPane(area).apply {
            border = RoundedBorder(theme.codeBackground, theme.border, 9)
            preferredSize = Dimension(420, height)
            viewport.background = theme.codeBackground
            themeScrollBars(this, theme)
        }

    private fun styleCheck(check: JCheckBox) {
        SectivUi.styleCheck(check, theme)
    }

    private fun styleControls() {
        listOf(
            maskSecretsCheck, autoScopeCheck, stateChangingCheck, temperatureCheck, showKeyCheck
        ).forEach { styleCheck(it) }
        SectivUi.styleCombo(tokenFieldCombo, theme)
        temperatureSpinner.isOpaque = false
        temperatureSpinner.border = RoundedBorder(theme.backgroundDeep, theme.border, 8)
        (temperatureSpinner.editor as? JSpinner.DefaultEditor)?.textField?.let {
            SectivUi.styleField(it, theme, fill = theme.backgroundDeep, padding = java.awt.Insets(4, 6, 4, 6), size = 10.5f)
        }
    }

    private fun tempNoOp() {
        // Keeps the initialization explicit and avoids a lazy-layout flash.
    }
}
