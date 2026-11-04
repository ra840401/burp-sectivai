package io.sectiv.burp.ui

import burp.api.montoya.MontoyaApi
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.scan.ScanEngine
import java.awt.BasicStroke
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.GridLayout
import java.awt.Point
import java.awt.RadialGradientPaint
import java.awt.RenderingHints
import java.awt.RenderingHints.KEY_INTERPOLATION
import java.awt.image.BufferedImage
import java.awt.image.BufferedImage.TYPE_INT_ARGB
import java.io.IOException
import javax.imageio.ImageIO
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import kotlin.math.min

class SectivPanel(
    api: MontoyaApi,
    private val store: SectivStore,
    engine: ScanEngine
) : JPanel(BorderLayout()) {

    private val theme = SectivTheme(api)
    private val nav = SectivNavHost(theme)

    private val dashboard = DashboardPanel(api, store, theme) {
        nav.selectedIndex = 1
    }
    private val skillsPanel = SkillsPanel(store, theme)
    private val scanPanel = ScanPanel(
        api,
        store,
        engine,
        theme,
        onOpenSettings = { nav.selectedIndex = 3 },
        onOpenSkills = { skillId ->
            nav.selectedIndex = 2
            skillsPanel.selectSkill(skillId)
        }
    )
    private val settingsPanel = SettingsPanel(store, theme)
    private val providerChip = StatusChip(theme)

    init {
        isOpaque = false
        background = theme.background

        nav.addTab("Dashboard", dashboard)
        nav.addTab("Scan", scanPanel)
        nav.addTab("Skills", skillsPanel)
        nav.addTab("Settings", settingsPanel)

        add(buildHeader(), BorderLayout.NORTH)
        add(nav.contentComponent, BorderLayout.CENTER)

        themeScrollBars(this, theme)
        store.onChange { SwingUtilities.invokeLater { refreshSummary() } }
        refreshSummary()
    }

    private fun buildHeader(): JPanel {
        val header = JPanel(BorderLayout()).apply {
            isOpaque = true
            background = theme.background
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.borderSoft),
                EmptyBorder(0, 20, 0, 20)
            )
            preferredSize = Dimension(0, 70)
        }

        val left = JPanel(FlowLayout(FlowLayout.LEFT, 20, 13)).apply {
            isOpaque = false
            add(brand())
            add(nav.navBar)
        }

        val right = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 18)).apply {
            isOpaque = false
            add(providerChip)
            add(PrimaryButton("New scan", theme).apply {
                addActionListener { nav.selectedIndex = 1 }
            })
        }

        header.add(left, BorderLayout.WEST)
        header.add(right, BorderLayout.EAST)
        return header
    }

    private fun brand(): JPanel = JPanel(FlowLayout(FlowLayout.LEFT, 11, 0)).apply {
        isOpaque = false
        add(LogoMark(theme))
        val text = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JLabel("Sectiv").apply {
                font = SectivFonts.semibold(18f)
                foreground = theme.text
            })
            add(JLabel("AI SECURITY REVIEW").apply {
                font = SectivFonts.mono(8.5f)
                foreground = theme.faint
            })
            add(JLabel("by zack0X01").apply {
                font = SectivFonts.mono(7.5f)
                foreground = theme.faint
            })
        }
        add(text)
    }

    private fun refreshSummary() {
        val state = store.state()
        val provider = state.settings.activeProvider()
        val missingKey = provider.requiresApiKey && provider.apiKey.isBlank()
        val text = when {
            provider.baseUrl.isBlank() -> "Configure provider"
            missingKey -> "${provider.name} · key missing"
            else -> "${provider.name} · ${provider.model}"
        }
        providerChip.set(text, !missingKey && provider.baseUrl.isNotBlank())
        providerChip.toolTipText = if (missingKey) "Add an API key in Settings" else provider.baseUrl
        nav.setBadgeAt(0, state.findings.size.takeIf { it > 0 }?.toString())
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.color = theme.background
            g2.fillRect(0, 0, width, height)
            g2.paint = RadialGradientPaint(
                Point(180, -120),
                1150f,
                floatArrayOf(0f, 1f),
                arrayOf(withAlpha(theme.accent, 18), withAlpha(theme.accent, 0))
            )
            g2.fillRect(0, 0, width, height)

            g2.color = Color(255, 255, 255, 5)
            g2.stroke = BasicStroke(1f)
            var x = 0
            while (x < width) {
                g2.drawLine(x, 0, x, min(height, 520))
                x += 52
            }
            var y = 0
            while (y < min(height, 520)) {
                g2.drawLine(0, y, width, y)
                y += 52
            }
        } finally {
            g2.dispose()
        }
        super.paintComponent(g)
    }

    fun close() {
        scanPanel.close()
    }
}

private class LogoMark(private val theme: SectivTheme) : JComponent() {
    init {
        preferredSize = Dimension(38, 38)
        minimumSize = preferredSize
        maximumSize = preferredSize
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.setRenderingHint(KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC)
            val image = LogoAsset.image
            if (image != null) {
                g2.drawImage(image, 0, 0, width, height, null)
            } else {
                g2.color = Color(0x0B, 0x11, 0x15)
                g2.fillRoundRect(0, 0, width - 1, height - 1, 9, 9)
                g2.color = Color(0xEE, 0xF1, 0xEF)
                g2.font = SectivFonts.bold(20f)
                g2.drawString("S", 9, 27)
                g2.color = theme.accent
                g2.fillOval(25, 6, 6, 6)
            }
        } finally {
            g2.dispose()
        }
    }
}

private object LogoAsset {
    val image: BufferedImage? by lazy {
        try {
            SectivPanel::class.java.getResourceAsStream("/logo.png")?.use { ImageIO.read(it) }
        } catch (_: IOException) {
            null
        }
    }
}
