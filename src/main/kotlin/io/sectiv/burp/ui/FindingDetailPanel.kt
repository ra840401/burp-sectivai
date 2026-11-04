package io.sectiv.burp.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.FindingStatus
import io.sectiv.burp.core.Json
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.report.ReportMeta
import io.sectiv.burp.report.ReportWriter
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.net.URI
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JEditorPane
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class FindingDetailPanel(
    private val api: MontoyaApi,
    private val theme: SectivTheme,
    private val store: SectivStore,
    private val onChanged: () -> Unit
) : JPanel(BorderLayout()) {

    private val cards = CardLayout()
    private var current: Finding? = null

    private val sendButton = PrimaryButton("Send to Repeater", theme)
    private val copyButton = ghostButton("Copy", theme)
    private val falsePositiveButton = ghostButton("False positive", theme)
    private val resolveButton = ghostButton("Resolve", theme)
    private val deleteButton = dangerButton("Delete", theme)

    private val overview = JEditorPane("text/html", "").apply {
        isEditable = false
        isOpaque = true
        background = theme.surface
        border = EmptyBorder(2, 2, 8, 8)
        putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true)
        font = theme.base
    }
    private val requestArea = rawArea()
    private val responseArea = rawArea()
    private val tabs = JTabbedPane().apply {
        font = theme.small.deriveFont(Font.BOLD)
        background = theme.surface
        foreground = theme.text
        border = EmptyBorder(0, 0, 0, 0)
        setUI(SectivTabbedPaneUI(theme))
        addTab("Overview", JScrollPane(overview).apply {
            border = BorderFactory.createEmptyBorder()
            viewport.background = theme.surface
            themeScrollBars(this, theme)
        })
        addTab("Request", scrollPane(requestArea, theme))
        addTab("Response", scrollPane(responseArea, theme))
    }

    private val titleArea = JTextArea().apply {
        isEditable = false
        isOpaque = false
        lineWrap = true
        wrapStyleWord = true
        font = theme.h2
        foreground = theme.text
        rows = 2
        border = EmptyBorder(0, 0, 0, 0)
        isFocusable = false
    }
    private val endpointArea = JTextArea().apply {
        isEditable = false
        isOpaque = false
        lineWrap = true
        wrapStyleWord = true
        font = theme.monoSmall
        foreground = theme.muted
        rows = 1
        border = EmptyBorder(0, 0, 0, 0)
        isFocusable = false
    }
    private val severityHolder = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
        isOpaque = false
        alignmentX = LEFT_ALIGNMENT
    }
    private val metaLine = JLabel().apply {
        font = theme.small
        foreground = theme.muted
        isOpaque = false
        alignmentX = LEFT_ALIGNMENT
    }

    init {
        isOpaque = false
        background = theme.surface
        layout = cards

        val empty = EmptyState(
            theme,
            "Select a finding",
            "Choose a row in the table to see the description, evidence and the captured request and response."
        )
        add(empty, "empty")

        val header = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = EmptyBorder(14, 16, 8, 16)
            add(severityHolder)
            add(Box.createVerticalStrut(8))
            add(titleArea)
            add(Box.createVerticalStrut(6))
            add(endpointArea)
            add(Box.createVerticalStrut(6))
            add(metaLine)
        }

        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
            isOpaque = false
            border = EmptyBorder(8, 12, 12, 12)
            add(copyButton)
            add(falsePositiveButton)
            add(resolveButton)
            add(deleteButton)
            add(sendButton)
        }

        val detail = JPanel(BorderLayout()).apply {
            isOpaque = true
            background = theme.surface
            add(header, BorderLayout.NORTH)
            add(tabs, BorderLayout.CENTER)
            add(buttons, BorderLayout.SOUTH)
        }
        add(detail, "detail")

        sendButton.addActionListener { sendToRepeater() }
        copyButton.addActionListener { copyFinding() }
        falsePositiveButton.addActionListener { setStatus(FindingStatus.FALSE_POSITIVE) }
        resolveButton.addActionListener { setStatus(FindingStatus.RESOLVED) }
        deleteButton.addActionListener { deleteFinding() }

        show(null)
    }

    fun show(finding: Finding?) {
        current = finding
        if (finding == null) {
            cards.show(this, "empty")
            return
        }
        cards.show(this, "detail")

        severityHolder.removeAll()
        severityHolder.add(
            Chip(
                finding.severity.label,
                theme.severityFg(finding.severity),
                theme.severityBg(finding.severity),
                theme.badge,
                showDot = true,
                dotColor = theme.severityDot(finding.severity),
                borderColor = theme.severityBorder(finding.severity)
            )
        )
        severityHolder.add(
            Chip(
                finding.confidence.label,
                theme.accent,
                theme.accentSoft,
                theme.badge,
                borderColor = withAlpha(theme.accent, 55)
            )
        )
        val statusColor = when (finding.status) {
            FindingStatus.OPEN -> theme.warning
            FindingStatus.TRIAGED -> theme.accent
            FindingStatus.RESOLVED -> theme.success
            FindingStatus.FALSE_POSITIVE -> theme.faint
        }
        severityHolder.add(JLabel("●").apply {
            font = theme.tiny
            foreground = statusColor
        })
        severityHolder.add(JLabel(finding.status.label).apply {
            font = theme.small
            foreground = statusColor
        })
        severityHolder.revalidate()
        severityHolder.repaint()

        titleArea.text = buildString {
            append("[").append(finding.severity.label).append("] ")
            append(finding.title.ifBlank { "Untitled finding" })
            finding.cvss?.let { append(" · CVSS ").append(it) }
        }
        val endpoint = listOf(finding.method, finding.url).filter { it.isNotBlank() }.joinToString(" ")
        endpointArea.text = endpoint.ifBlank { "No endpoint recorded" }
        endpointArea.rows = if (endpoint.length > 110) 2 else 1
        metaLine.text = buildString {
            if (finding.skillName.isNotBlank()) append("Skill: ${finding.skillName}    ")
            if (finding.cwe.isNotBlank()) append("${finding.cwe}    ")
            finding.cvss?.let { append("CVSS $it    ") }
            append(DateTimeFormatter.ofPattern("MMM d, yyyy HH:mm")
                .withZone(ZoneId.systemDefault())
                .format(Instant.ofEpochMilli(finding.createdAt)))
        }

        overview.text = overviewHtml(finding)
        overview.caretPosition = 0
        requestArea.text = finding.requestRaw.ifBlank { "No raw request stored for this finding." }
        requestArea.caretPosition = 0
        responseArea.text = finding.responseRaw.ifBlank { "No raw response stored for this finding." }
        responseArea.caretPosition = 0

        sendButton.isEnabled = finding.requestRaw.isNotBlank()
        falsePositiveButton.isEnabled = finding.status != FindingStatus.FALSE_POSITIVE
        resolveButton.isEnabled = finding.status != FindingStatus.RESOLVED
    }

    private fun rawArea(): JTextArea = JTextArea().apply {
        isEditable = false
        font = theme.monoSmall
        background = theme.codeBackground
        foreground = theme.codeText
        caretColor = theme.codeText
        border = EmptyBorder(10, 12, 10, 12)
        lineWrap = false
    }

    private fun overviewHtml(finding: Finding): String {
        val e = Json::escapeHtml
        val muted = hex(theme.muted)
        val text = hex(theme.text)
        val codeBg = hex(theme.codeBackground)
        val codeText = "#D9E2F2"
        val font = theme.base.family
        return buildString {
            append("<html><body bgcolor='${hex(theme.surface)}' text='$text'>")
            append("<div style='font-family:$font;font-size:${theme.base.size}pt;color:$text'>")
            append("<table width='100%' cellpadding='2' cellspacing='0'>")
            if (finding.skillName.isNotBlank()) metaRow(this, "Skill", e(finding.skillName), muted, text)
            if (finding.cwe.isNotBlank()) metaRow(this, "Weakness", e(finding.cwe), muted, text)
            if (finding.cve.isNotBlank()) metaRow(this, "CVE", e(finding.cve), muted, text)
            finding.cvss?.let { metaRow(this, "CVSS", it.toString(), muted, text) }
            metaRow(this, "Source", if (finding.source == "identity-swap") "Active identity-swap check" else "AI review", muted, text)
            append("</table>")

            section(this, "Description", finding.description, muted, text)
            section(this, "Steps to Reproduce", finding.stepsToReproduce, muted, text)
            section(this, "Impact", finding.impact, muted, text)
            if (finding.evidence.isNotBlank()) {
                append("<p style='margin:14px 0 4px'><b><font color='$muted'>EVIDENCE</font></b></p>")
                append("<table width='100%' cellpadding='10' cellspacing='0' bgcolor='$codeBg'><tr><td>")
                append("<font face='monospace' color='$codeText'>").append(htmlPre(finding.evidence)).append("</font>")
                append("</td></tr></table>")
            }
            if (finding.poc.isNotBlank()) {
                val pocLabel = when (finding.pocType.lowercase()) {
                    "html" -> "POC · HTML PAGE"
                    "python" -> "POC · PYTHON"
                    "curl" -> "POC · CURL"
                    else -> "POC"
                }
                append("<p style='margin:14px 0 4px'><b><font color='$muted'>${e(pocLabel)}</font></b></p>")
                append("<table width='100%' cellpadding='10' cellspacing='0' bgcolor='$codeBg'><tr><td>")
                append("<font face='monospace' color='$codeText'>").append(htmlPre(finding.poc)).append("</font>")
                append("</td></tr></table>")
            }
            section(this, "Remediation", finding.remediation, muted, text)
            append("</div></body></html>")
        }
    }

    private fun metaRow(builder: StringBuilder, name: String, value: String, muted: String, text: String) {
        builder.append("<tr><td width='120' valign='top'><font color='$muted'>")
            .append(Json.escapeHtml(name))
            .append("</font></td><td><font color='$text'>")
            .append(value)
            .append("</font></td></tr>")
    }

    private fun section(builder: StringBuilder, name: String, value: String, muted: String, text: String) {
        if (value.isBlank()) return
        builder.append("<p style='margin:14px 0 4px'><b><font color='$muted'>")
            .append(name.uppercase())
            .append("</font></b></p><div style='color:$text'>")
            .append(htmlPre(value))
            .append("</div>")
    }

    private fun setStatus(status: FindingStatus) {
        val finding = current ?: return
        store.updateFinding(finding.id) { it.copy(status = status) }
        show(finding.copy(status = status))
        onChanged()
    }

    private fun deleteFinding() {
        val finding = current ?: return
        if (!Dialogs.confirm(this, "Delete finding", "Delete \"${finding.title}\"? This cannot be undone.")) return
        store.deleteFinding(finding.id)
        show(null)
        onChanged()
    }

    private fun copyFinding() {
        val finding = current ?: return
        val markdown = ReportWriter.toMarkdown(
            listOf(finding),
            ReportMeta(title = finding.title, provider = store.state().settings.activeProvider().name)
        )
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(markdown), null)
        copyButton.text = "Copied"
        javax.swing.Timer(1400) { copyButton.text = "Copy" }.apply { isRepeats = false }.start()
    }

    private fun sendToRepeater() {
        val finding = current ?: return
        if (finding.requestRaw.isBlank()) {
            Dialogs.info(this, "No request", "This finding does not have a captured request attached.")
            return
        }
        try {
            val uri = runCatching { URI(finding.url) }.getOrNull()
            val host = finding.hostLabel.ifBlank { uri?.host.orEmpty() }
            if (host.isBlank()) {
                Dialogs.error(this, "Cannot send", "The finding has no host information.")
                return
            }
            val scheme = uri?.scheme?.lowercase()
            val secure = when (scheme) {
                "https" -> true
                "http" -> false
                else -> if (finding.port > 0) finding.secure else true
            }
            val port = when {
                scheme == "https" -> 443
                scheme == "http" -> 80
                finding.port > 0 -> finding.port
                secure -> 443
                else -> 80
            }
            val service = HttpService.httpService(host, port, secure)
            val request = HttpRequest.httpRequest(service, finding.requestRaw)
            api.repeater().sendToRepeater(request, "Sectiv")
        } catch (e: Exception) {
            Dialogs.error(this, "Could not send to Repeater", e.message ?: e.javaClass.simpleName)
        }
    }

    private fun hex(color: Color): String = String.format("#%02X%02X%02X", color.red, color.green, color.blue)
}
