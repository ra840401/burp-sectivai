package io.sectiv.burp.ui

import io.sectiv.burp.core.Json
import io.sectiv.burp.core.Severity
import io.sectiv.burp.scan.LogLevel
import java.awt.BasicStroke
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Cursor
import java.awt.Desktop
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.FontMetrics
import java.awt.GradientPaint
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Insets
import java.awt.RadialGradientPaint
import java.awt.RenderingHints
import java.awt.Toolkit
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.geom.Point2D
import java.net.URI
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.Icon
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextPane
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.border.Border
import javax.swing.border.CompoundBorder
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder
import javax.swing.plaf.basic.BasicScrollBarUI
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.text.JTextComponent
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import javax.swing.text.StyledDocument

fun htmlPre(text: String): String =
    Json.escapeHtml(text)
        .replace("  ", "&nbsp;&nbsp;")
        .replace("\n", "<br>")

fun label(text: String, font: Font, color: Color): JLabel =
    JLabel(text).apply {
        this.font = font
        foreground = color
        isOpaque = false
    }

fun withAlpha(color: Color, alpha: Int): Color = Color(color.red, color.green, color.blue, alpha.coerceIn(0, 255))

/** Rounded fill + stroke used by inputs, chips and panels. */
class RoundedBorder(
    private val fill: Color?,
    private val stroke: Color?,
    private val radius: Int = 9,
    private val strokeWidth: Float = 1f
) : Border {
    override fun getBorderInsets(c: Component?): Insets = Insets(1, 1, 1, 1)
    override fun isBorderOpaque(): Boolean = fill != null && fill.alpha == 255

    override fun paintBorder(c: Component?, g: Graphics, x: Int, y: Int, w: Int, h: Int) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            if (fill != null) {
                g2.color = fill
                g2.fillRoundRect(x, y, w - 1, h - 1, radius, radius)
            }
            if (stroke != null) {
                g2.color = stroke
                g2.stroke = BasicStroke(strokeWidth)
                g2.drawRoundRect(x, y, w - 1, h - 1, radius, radius)
            }
        } finally {
            g2.dispose()
        }
    }
}

object SectivUi {
    fun styleField(
        field: JTextComponent,
        theme: SectivTheme,
        fill: Color = theme.backgroundDeep,
        padding: Insets = Insets(8, 10, 8, 10),
        radius: Int = 8,
        mono: Boolean = false,
        size: Float = 11.5f
    ) {
        field.isOpaque = true
        field.background = fill
        field.foreground = theme.text
        field.caretColor = theme.text
        field.selectionColor = theme.accentSoft
        field.selectedTextColor = theme.text
        field.font = if (mono) SectivFonts.mono(size) else SectivFonts.regular(size)
        field.border = CompoundBorder(
            RoundedBorder(null, theme.border, radius),
            EmptyBorder(padding.top, padding.left, padding.bottom, padding.right)
        )
    }

    fun styleTextArea(area: JTextArea, theme: SectivTheme, mono: Boolean = true) {
        area.isOpaque = false
        area.background = theme.codeBackground
        area.foreground = theme.codeText
        area.caretColor = theme.codeText
        area.selectionColor = theme.accentSoft
        area.selectedTextColor = theme.text
        area.font = if (mono) theme.monoSmall else theme.base
        area.border = EmptyBorder(9, 11, 9, 11)
    }

    fun styleCombo(combo: JComboBox<*>, theme: SectivTheme) {
        combo.font = theme.small
        combo.background = theme.surfaceAlt
        combo.foreground = theme.text
        combo.isOpaque = true
        combo.border = RoundedBorder(null, theme.border, 8)
        combo.setUI(SectivComboBoxUI(theme))
        combo.maximumRowCount = 12
        combo.renderer = object : javax.swing.DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                list: javax.swing.JList<*>?,
                value: Any?,
                index: Int,
                isSelected: Boolean,
                cellHasFocus: Boolean
            ): Component {
                val c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
                c.font = theme.small
                c.background = if (isSelected) theme.surfaceRaised else theme.surfaceAlt
                c.foreground = theme.text
                return c
            }
        }
    }

    fun styleCheck(check: JCheckBox, theme: SectivTheme) {
        check.font = theme.small
        check.foreground = theme.textSoft
        check.isOpaque = false
        check.isFocusPainted = false
        check.border = EmptyBorder(0, 0, 0, 0)
        check.icon = CheckIcon(theme, false)
        check.selectedIcon = CheckIcon(theme, true)
        check.disabledIcon = CheckIcon(theme, false, true)
        check.disabledSelectedIcon = CheckIcon(theme, true, true)
        check.pressedIcon = CheckIcon(theme, check.isSelected)
    }

    fun styleTable(table: JTable, theme: SectivTheme) {
        table.background = theme.surface
        table.foreground = theme.textSoft
        table.selectionBackground = theme.tableSelection
        table.selectionForeground = theme.text
        table.font = SectivFonts.regular(12f)
        table.rowHeight = 42
        table.setShowGrid(false)
        table.intercellSpacing = Dimension(0, 0)
        table.fillsViewportHeight = true
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        table.autoCreateRowSorter = false
        table.setShowHorizontalLines(false)
        table.setShowVerticalLines(false)
        val header = table.tableHeader
        header.background = Color(0x11, 0x17, 0x1C)
        header.foreground = theme.faint
        header.font = theme.monoMedium.deriveFont(Font.BOLD)
        header.reorderingAllowed = false
        header.border = BorderFactory.createMatteBorder(0, 0, 1, 0, theme.borderSoft)
        table.putClientProperty("terminateEditOnFocusLost", true)
    }

    fun styleScrollPane(scroll: JScrollPane, theme: SectivTheme, radius: Int = 9) {
        scroll.border = RoundedBorder(theme.surface, theme.border, radius)
        scroll.viewport.background = theme.surface
        scroll.background = theme.surface
        scroll.verticalScrollBar.unitIncrement = 18
        scroll.horizontalScrollBar.unitIncrement = 18
        themeScrollBars(scroll, theme)
    }
}

private class SectivComboBoxUI(private val theme: SectivTheme) : javax.swing.plaf.basic.BasicComboBoxUI() {
    override fun paintCurrentValueBackground(g: Graphics, bounds: java.awt.Rectangle, hasFocus: Boolean) {
        g.color = theme.surfaceAlt
        g.fillRect(bounds.x, bounds.y, bounds.width, bounds.height)
    }

    override fun paintCurrentValue(g: Graphics, bounds: java.awt.Rectangle, hasFocus: Boolean) {
        val renderer = comboBox.renderer ?: return
        val index = comboBox.selectedIndex
        val value = comboBox.selectedItem
        val c = renderer.getListCellRendererComponent(listBox, value, index, false, false)
        if (c is JComponent) {
            c.isOpaque = true
            c.background = theme.surfaceAlt
            c.foreground = theme.text
            c.font = theme.small
            c.border = EmptyBorder(0, 8, 0, 4)
            c.setBounds(0, 0, bounds.width, bounds.height)
        }
        val g2 = g.create(bounds.x, bounds.y, bounds.width, bounds.height)
        try {
            c.paint(g2)
        } finally {
            g2.dispose()
        }
    }

    override fun createArrowButton(): JButton = object : JButton() {
        init {
            isOpaque = false
            isContentAreaFilled = false
            isBorderPainted = false
            isFocusable = false
            preferredSize = Dimension(22, 22)
            cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        }

        override fun paintComponent(g: Graphics) {
            val g2 = g.create() as Graphics2D
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                g2.color = theme.muted
                g2.stroke = BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
                val cx = width / 2
                val cy = height / 2 - 1
                g2.drawLine(cx - 3, cy - 1, cx, cy + 2)
                g2.drawLine(cx, cy + 2, cx + 3, cy - 1)
            } finally {
                g2.dispose()
            }
        }
    }

    override fun createPopup(): javax.swing.plaf.basic.ComboPopup =
        object : javax.swing.plaf.basic.BasicComboPopup(comboBox) {
            init {
                isOpaque = true
                background = theme.surfaceAlt
                border = RoundedBorder(theme.surfaceAlt, theme.border, 8)
            }
        }
}

private class CheckIcon(
    private val theme: SectivTheme,
    private val checked: Boolean,
    private val disabled: Boolean = false
) : Icon {
    override fun getIconWidth(): Int = 14
    override fun getIconHeight(): Int = 14

    override fun paintIcon(c: Component?, g: Graphics, x: Int, y: Int) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            if (checked) {
                g2.color = if (disabled) withAlpha(theme.accent, 80) else theme.accent
                g2.fillRoundRect(x, y, 14, 14, 5, 5)
                g2.color = theme.accentInk
                g2.stroke = BasicStroke(1.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
                g2.drawLine(x + 3, y + 7, x + 6, y + 10)
                g2.drawLine(x + 6, y + 10, x + 11, y + 4)
            } else {
                g2.color = theme.backgroundDeep
                g2.fillRoundRect(x, y, 14, 14, 5, 5)
                g2.color = if (disabled) theme.border else theme.borderStrong
                g2.stroke = BasicStroke(1f)
                g2.drawRoundRect(x, y, 13, 13, 5, 5)
            }
        } finally {
            g2.dispose()
        }
    }
}

class PrimaryButton(text: String, private val theme: SectivTheme) : JButton(text) {
    init {
        font = SectivFonts.semibold(12f)
        foreground = theme.accentInk
        isFocusPainted = false
        isContentAreaFilled = false
        isBorderPainted = false
        isOpaque = false
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        border = EmptyBorder(9, 15, 9, 15)
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = when {
                !isEnabled -> theme.surfaceRaised
                model.isPressed -> Color(0xD9, 0x62, 0x22)
                model.isRollover -> theme.accentHover
                else -> theme.accent
            }
            if (isEnabled) {
                g2.fillRoundRect(0, 0, width, height, 9, 9)
            } else {
                g2.fillRoundRect(0, 0, width, height, 9, 9)
            }
        } finally {
            g2.dispose()
        }
        super.paintComponent(g)
    }
}

class SecondaryButton(
    text: String,
    private val theme: SectivTheme,
    private val danger: Boolean = false
) : JButton(text) {
    init {
        font = SectivFonts.medium(11.5f)
        foreground = if (danger) Color(0xFF, 0x8E, 0x8E) else theme.textSoft
        isFocusPainted = false
        isContentAreaFilled = false
        isBorderPainted = false
        isOpaque = false
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        border = EmptyBorder(7, 11, 7, 11)
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            val fill = when {
                danger && model.isRollover -> Color(0x2E, 0x17, 0x19)
                danger -> Color(0x21, 0x15, 0x17)
                model.isRollover -> theme.surfaceHover
                else -> theme.surfaceAlt
            }
            g2.color = fill
            g2.fillRoundRect(0, 0, width, height, 9, 9)
            g2.color = when {
                danger -> Color(0x55, 0x2B, 0x30)
                model.isRollover -> theme.borderStrong
                else -> theme.border
            }
            g2.stroke = BasicStroke(1f)
            g2.drawRoundRect(0, 0, width - 1, height - 1, 9, 9)
        } finally {
            g2.dispose()
        }
        super.paintComponent(g)
    }
}

fun ghostButton(text: String, theme: SectivTheme): JButton = SecondaryButton(text, theme)

fun dangerButton(text: String, theme: SectivTheme): JButton = SecondaryButton(text, theme, danger = true)

open class RoundedPanel(
    val theme: SectivTheme,
    var fill: Color = theme.surface,
    var borderColor: Color = theme.border,
    var radius: Int = 14
) : JPanel() {
    init {
        isOpaque = false
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = fill
            g2.fillRoundRect(0, 0, width - 1, height - 1, radius, radius)
            g2.paint = GradientPaint(
                0f, 0f, withAlpha(Color.WHITE, 6),
                0f, height.toFloat(), Color(0, 0, 0, 0)
            )
            g2.fillRoundRect(0, 0, width - 1, height - 1, radius, radius)
            if (borderColor.alpha > 0) {
                g2.color = borderColor
                g2.stroke = BasicStroke(1f)
                g2.drawRoundRect(0, 0, width - 1, height - 1, radius, radius)
            }
        } finally {
            g2.dispose()
        }
        super.paintComponent(g)
    }
}

class Card(theme: SectivTheme, title: String? = null) : RoundedPanel(theme) {
    init {
        layout = BorderLayout(0, 10)
        border = EmptyBorder(14, 16, 16, 16)
        if (title != null) {
            add(
                JLabel(title).apply {
                    font = SectivFonts.semibold(13f)
                    foreground = theme.textSoft
                    isOpaque = false
                },
                BorderLayout.NORTH
            )
        }
    }

    override fun getMaximumSize(): Dimension = Dimension(Int.MAX_VALUE, preferredSize.height)
}

class Chip(
    text: String,
    private val fg: Color,
    private val bg: Color,
    font: Font,
    private val showDot: Boolean = false,
    private val dotColor: Color? = null,
    private val borderColor: Color? = null
) : JComponent() {
    var text: String = text
        set(value) {
            field = value
            revalidate()
            repaint()
        }

    init {
        this.font = font
        isOpaque = false
        border = EmptyBorder(3, 8, 3, 8)
    }

    override fun getPreferredSize(): Dimension {
        val metrics = getFontMetrics(font)
        val insets = insets
        val dot = if (showDot) 11 else 0
        return Dimension(
            metrics.stringWidth(text) + insets.left + insets.right + dot,
            metrics.height + insets.top + insets.bottom
        )
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = bg
            g2.fillRoundRect(0, 0, width - 1, height - 1, height, height)
            if (borderColor != null) {
                g2.color = borderColor
                g2.stroke = BasicStroke(1f)
                g2.drawRoundRect(0, 0, width - 1, height - 1, height, height)
            }
            var x = 8
            if (showDot) {
                g2.color = dotColor ?: fg
                g2.fillOval(x, height / 2 - 2, 4, 4)
                x += 7
            }
            g2.color = fg
            g2.font = font
            val metrics = g2.fontMetrics
            g2.drawString(text, x, (height - metrics.height) / 2 + metrics.ascent)
        } finally {
            g2.dispose()
        }
    }
}

class PageHeader(
    private val theme: SectivTheme,
    eyebrowText: String,
    titleText: String,
    subtitleText: String,
    actions: JComponent? = null
) : JPanel(BorderLayout()) {
    private val subtitle = JLabel().apply {
        font = theme.small
        foreground = theme.muted
        isOpaque = false
    }

    init {
        isOpaque = false
        val left = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JLabel(eyebrowText.uppercase()).apply {
                font = theme.eyebrow
                foreground = theme.accent
                isOpaque = false
            })
            add(Box.createVerticalStrut(7))
            add(JLabel(titleText).apply {
                font = theme.h1
                foreground = theme.text
                isOpaque = false
            })
            add(Box.createVerticalStrut(6))
            add(subtitle)
        }
        add(left, BorderLayout.WEST)
        if (actions != null) {
            val wrapper = JPanel(FlowLayout(FlowLayout.RIGHT, 7, 0)).apply {
                isOpaque = false
                add(actions)
            }
            add(wrapper, BorderLayout.EAST)
        }
        subtitle.text = subtitleText
        preferredSize = Dimension(0, 84)
    }

    fun setSubtitle(text: String) {
        subtitle.text = text
    }
}

class StepBadge(text: String, private val theme: SectivTheme) : JComponent() {
    init {
        preferredSize = Dimension(20, 20)
        minimumSize = preferredSize
        maximumSize = preferredSize
        toolTipText = text
    }

    private val caption = text

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = withAlpha(theme.accent, 30)
            g2.fillRoundRect(0, 0, 19, 19, 6, 6)
            g2.color = withAlpha(theme.accent, 65)
            g2.stroke = BasicStroke(1f)
            g2.drawRoundRect(0, 0, 19, 19, 6, 6)
            g2.color = theme.accent
            g2.font = SectivFonts.monoMedium(9f)
            val metrics = g2.fontMetrics
            g2.drawString(caption, (20 - metrics.stringWidth(caption)) / 2, (20 - metrics.height) / 2 + metrics.ascent)
        } finally {
            g2.dispose()
        }
    }
}

class SeverityCard(
    private val severity: Severity,
    private val theme: SectivTheme,
    private val subtitle: String,
    onClick: () -> Unit
) : JComponent() {
    private var count = 0
    private var hover = false
    private val sparkHeights = listOf(7, 12, 9, 16, 11)

    init {
        preferredSize = Dimension(200, 112)
        minimumSize = Dimension(160, 100)
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        toolTipText = "Show ${severity.label} findings"
        addMouseListener(object : MouseAdapter() {
            override fun mouseEntered(e: MouseEvent) {
                hover = true
                repaint()
            }

            override fun mouseExited(e: MouseEvent) {
                hover = false
                repaint()
            }

            override fun mouseClicked(e: MouseEvent) = onClick()
        })
    }

    fun setCount(value: Int) {
        if (count == value) return
        count = value
        repaint()
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            val fillTop = if (hover) theme.surfaceHover else theme.surfaceAlt
            g2.paint = GradientPaint(0f, 0f, fillTop, 0f, height.toFloat(), theme.surface)
            g2.fillRoundRect(0, 0, width - 1, height - 1, 13, 13)

            // A very soft severity glow, no coloured border.
            val dot = theme.severityDot(severity)
            g2.paint = RadialGradientPaint(
                Point2D.Float(width - 30f, 16f),
                64f,
                floatArrayOf(0f, 1f),
                arrayOf(withAlpha(dot, 16), withAlpha(dot, 0))
            )
            g2.fillRoundRect(0, 0, width - 1, height - 1, 13, 13)

            g2.color = if (hover) theme.borderStrong else theme.border
            g2.stroke = BasicStroke(1f)
            g2.drawRoundRect(0, 0, width - 1, height - 1, 13, 13)

            g2.color = dot
            g2.fillOval(16, 21, 6, 6)

            g2.font = SectivFonts.semibold(9.5f)
            g2.color = theme.severityFg(severity)
            g2.drawString(severity.label.uppercase(), 28, 28)

            // Sparkline
            var sx = width - 48
            for (h in sparkHeights) {
                g2.color = withAlpha(dot, 120)
                g2.fillRoundRect(sx, 26 - h, 3, h, 2, 2)
                sx += 5
            }

            g2.font = SectivFonts.bold(30f)
            g2.color = theme.text
            g2.drawString(count.toString(), 16, 74)

            g2.font = SectivFonts.regular(10f)
            g2.color = theme.faint
            g2.drawString(subtitle, 16, 93)
        } finally {
            g2.dispose()
        }
    }
}

class StatusChip(private val theme: SectivTheme) : JComponent() {
    private var text = "No provider configured"
    private var good = false

    init {
        isOpaque = false
        border = EmptyBorder(5, 10, 5, 10)
        updateSize()
    }

    fun set(text: String, good: Boolean) {
        this.text = text
        this.good = good
        updateSize()
        revalidate()
        repaint()
    }

    private fun updateSize() {
        val metrics = getFontMetrics(SectivFonts.regular(10.5f))
        preferredSize = Dimension(metrics.stringWidth(text) + 34, 30)
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = theme.surfaceAlt
            g2.fillRoundRect(0, 0, width - 1, height - 1, 9, 9)
            g2.color = theme.border
            g2.stroke = BasicStroke(1f)
            g2.drawRoundRect(0, 0, width - 1, height - 1, 9, 9)
            g2.color = if (good) theme.accent else theme.warning
            g2.fillOval(10, height / 2 - 3, 6, 6)
            g2.color = theme.textSoft
            g2.font = SectivFonts.regular(10.5f)
            val metrics = g2.fontMetrics
            g2.drawString(text, 23, (height - metrics.height) / 2 + metrics.ascent)
        } finally {
            g2.dispose()
        }
    }
}

class EmptyState(
    theme: SectivTheme,
    title: String,
    message: String,
    actionLabel: String? = null,
    action: (() -> Unit)? = null
) : JPanel() {
    init {
        isOpaque = false
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        border = EmptyBorder(32, 30, 32, 30)
        add(Box.createVerticalGlue())
        add(EmptyIcon(theme).apply { alignmentX = Component.CENTER_ALIGNMENT })
        add(Box.createVerticalStrut(14))
        add(
            JLabel(title).apply {
                font = theme.h2
                foreground = theme.text
                alignmentX = Component.CENTER_ALIGNMENT
            }
        )
        add(Box.createVerticalStrut(6))
        add(
            WrapLabel(message, theme.base, theme.muted, 390, center = true).apply {
                alignmentX = Component.CENTER_ALIGNMENT
            }
        )
        if (actionLabel != null && action != null) {
            add(Box.createVerticalStrut(18))
            add(
                PrimaryButton(actionLabel, theme).apply {
                    alignmentX = Component.CENTER_ALIGNMENT
                    addActionListener { action() }
                }
            )
        }
        add(Box.createVerticalGlue())
    }
}

private class EmptyIcon(private val theme: SectivTheme) : JComponent() {
    init {
        preferredSize = Dimension(52, 52)
        minimumSize = preferredSize
        maximumSize = preferredSize
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = theme.surfaceAlt
            g2.fillOval(2, 2, 46, 46)
            g2.color = theme.borderStrong
            g2.stroke = BasicStroke(1.6f)
            g2.drawOval(9, 9, 30, 30)
            g2.drawLine(37, 37, 47, 47)
            g2.color = theme.accent
            g2.fillOval(21, 21, 6, 6)
        } finally {
            g2.dispose()
        }
    }
}

class LinkLabel(text: String, url: String, theme: SectivTheme) : JLabel(text) {
    init {
        font = SectivFonts.regular(10f)
        foreground = theme.accent
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        toolTipText = url
        addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                try {
                    if (Desktop.isDesktopSupported()) Desktop.getDesktop().browse(URI(url))
                } catch (_: Exception) {
                }
            }
        })
    }
}

class PlaceholderTextArea(private val theme: SectivTheme, private val placeholder: String) : JTextArea() {
    init {
        isOpaque = false
        background = theme.surfaceAlt
        foreground = theme.text
        caretColor = theme.text
        selectionColor = theme.accentSoft
        selectedTextColor = theme.text
        font = theme.base
        lineWrap = true
        wrapStyleWord = true
        border = EmptyBorder(9, 11, 9, 11)
        addFocusListener(object : FocusAdapter() {
            override fun focusGained(e: FocusEvent) = repaint()
            override fun focusLost(e: FocusEvent) = repaint()
        })
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        if (text.isEmpty() && !hasFocus()) {
            val g2 = g.create() as Graphics2D
            try {
                g2.font = font.deriveFont(Font.ITALIC)
                g2.color = theme.faint
                val metrics = g2.fontMetrics
                val maxWidth = width - insets.left - insets.right - 6
                var y = insets.top + metrics.ascent
                for (rawLine in placeholder.split('\n')) {
                    val indent = rawLine.takeWhile { it == ' ' }
                    val words = rawLine.trim().split(' ').filter { it.isNotEmpty() }
                    if (words.isEmpty()) {
                        y += metrics.height
                        if (y > height - insets.bottom) break
                        continue
                    }
                    var line = StringBuilder(indent)
                    for (word in words) {
                        val candidate = if (line.toString().trim().isEmpty()) "$indent$word" else "$line $word"
                        if (metrics.stringWidth(candidate) > maxWidth && line.length > indent.length) {
                            g2.drawString(line.toString(), insets.left + 4, y)
                            y += metrics.height
                            line = StringBuilder(indent + word)
                            if (y > height - insets.bottom - metrics.height) break
                        } else {
                            line = StringBuilder(candidate)
                        }
                    }
                    if (line.isNotEmpty() && y <= height - insets.bottom - metrics.height) {
                        g2.drawString(line.toString(), insets.left + 4, y)
                        y += metrics.height
                    }
                    if (y > height - insets.bottom - metrics.height) break
                }
            } finally {
                g2.dispose()
            }
        }
    }
}

class SectivScrollBarUI(private val theme: SectivTheme) : BasicScrollBarUI() {
    private val zero = object : JButton() {
        init {
            preferredSize = Dimension(0, 0)
            minimumSize = Dimension(0, 0)
            maximumSize = Dimension(0, 0)
            isFocusable = false
        }
    }

    override fun createDecreaseButton(orientation: Int): JButton = zero
    override fun createIncreaseButton(orientation: Int): JButton = zero

    override fun paintTrack(g: Graphics, c: JComponent, trackBounds: java.awt.Rectangle) {
        g.color = theme.surfaceAlt
        g.fillRect(trackBounds.x, trackBounds.y, trackBounds.width, trackBounds.height)
    }

    override fun paintThumb(g: Graphics, c: JComponent, thumbBounds: java.awt.Rectangle) {
        if (thumbBounds.isEmpty) return
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = theme.borderStrong
            g2.fillRoundRect(
                thumbBounds.x + 2,
                thumbBounds.y + 2,
                (thumbBounds.width - 4).coerceAtLeast(3),
                (thumbBounds.height - 4).coerceAtLeast(3),
                6,
                6
            )
        } finally {
            g2.dispose()
        }
    }
}

fun themeScrollBars(root: Component, theme: SectivTheme) {
    if (root is JScrollPane) {
        root.verticalScrollBar.apply {
            setUI(SectivScrollBarUI(theme))
            preferredSize = Dimension(10, 0)
        }
        root.horizontalScrollBar.apply {
            setUI(SectivScrollBarUI(theme))
            preferredSize = Dimension(0, 10)
        }
    }
    if (root is java.awt.Container) {
        root.components.forEach { themeScrollBars(it, theme) }
    }
}

class PlaceholderTextField(
    private val theme: SectivTheme,
    private val placeholder: String
) : JTextField() {
    init {
        addFocusListener(object : FocusAdapter() {
            override fun focusGained(e: FocusEvent) = repaint()
            override fun focusLost(e: FocusEvent) = repaint()
        })
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        if (text.isEmpty() && !hasFocus()) {
            val g2 = g.create() as Graphics2D
            try {
                g2.font = font.deriveFont(Font.ITALIC)
                g2.color = theme.faint
                val metrics = g2.fontMetrics
                g2.drawString(
                    placeholder,
                    insets.left + 1,
                    (height - metrics.height) / 2 + metrics.ascent
                )
            } finally {
                g2.dispose()
            }
        }
    }
}

class LogPane(private val theme: SectivTheme) : JTextPane() {
    private val timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())
    private val styles = mutableMapOf<LogLevel, SimpleAttributeSet>()

    init {
        isEditable = false
        isOpaque = true
        background = theme.codeBackground
        foreground = theme.codeText
        font = SectivFonts.mono(10.5f)
        caretColor = theme.codeText
        border = EmptyBorder(10, 13, 10, 13)
        for (level in LogLevel.entries) {
            val attrs = SimpleAttributeSet()
            StyleConstants.setForeground(attrs, colorFor(level))
            StyleConstants.setFontFamily(attrs, SectivFonts.mono.family)
            StyleConstants.setFontSize(attrs, 10)
            styles[level] = attrs
        }
    }

    fun append(level: LogLevel, message: String) {
        val doc = document as StyledDocument
        val stamp = SimpleAttributeSet()
        StyleConstants.setForeground(stamp, Color(0x4F, 0x5C, 0x67))
        StyleConstants.setFontFamily(stamp, SectivFonts.mono.family)
        StyleConstants.setFontSize(stamp, 10)
        doc.insertString(doc.length, "${timeFormat.format(Instant.now())}  ", stamp)
        doc.insertString(doc.length, message + "\n", styles[level] ?: styles[LogLevel.INFO])
        if (doc.length > 350_000) {
            doc.remove(0, minOf(80_000, doc.length / 4))
        }
        setCaretPosition(doc.length)
    }

    fun clearLog() {
        text = ""
    }

    private fun colorFor(level: LogLevel): Color = when (level) {
        LogLevel.INFO -> Color(0xA9, 0xB7, 0xC6)
        LogLevel.SUCCESS -> Color(0x72, 0xE9, 0xA0)
        LogLevel.WARN -> Color(0xFF, 0xBD, 0x6F)
        LogLevel.ERROR -> Color(0xFF, 0x8B, 0x8B)
    }
}

class TextCellRenderer(
    private val theme: SectivTheme,
    private val mono: Boolean = false,
    private val alignment: Int = SwingConstants.LEFT
) : DefaultTableCellRenderer() {
    init {
        horizontalAlignment = alignment
    }

    override fun getTableCellRendererComponent(
        table: JTable,
        value: Any?,
        isSelected: Boolean,
        hasFocus: Boolean,
        row: Int,
        column: Int
    ): Component {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        font = if (mono) theme.mono else SectivFonts.regular(12f)
        foreground = if (isSelected) theme.text else theme.textSoft
        background = if (isSelected) table.selectionBackground else table.background
        border = EmptyBorder(0, 10, 0, 8)
        return this
    }
}

class SeverityRenderer(private val theme: SectivTheme) : DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(
        table: JTable,
        value: Any?,
        isSelected: Boolean,
        hasFocus: Boolean,
        row: Int,
        column: Int
    ): Component {
        val severity = value as? Severity ?: Severity.INFO
        val panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 7))
        panel.isOpaque = true
        panel.background = if (isSelected) table.selectionBackground else table.background
        panel.add(
            Chip(
                severity.label,
                theme.severityFg(severity),
                theme.severityBg(severity),
                theme.badge,
                showDot = true,
                dotColor = theme.severityDot(severity),
                borderColor = theme.severityBorder(severity)
            )
        )
        return panel
    }
}

class StatusRenderer(private val theme: SectivTheme) : DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(
        table: JTable,
        value: Any?,
        isSelected: Boolean,
        hasFocus: Boolean,
        row: Int,
        column: Int
    ): Component {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        font = theme.small
        value?.toString()?.let {
            foreground = when (it) {
                "Open" -> theme.warning
                "Triaged" -> theme.accent
                "Resolved" -> theme.success
                "False positive" -> theme.faint
                else -> theme.muted
            }
        }
        background = if (isSelected) table.selectionBackground else table.background
        border = EmptyBorder(0, 10, 0, 6)
        return this
    }
}

class BooleanRenderer(private val theme: SectivTheme) : JCheckBox(), javax.swing.table.TableCellRenderer {
    init {
        isOpaque = true
        horizontalAlignment = SwingConstants.CENTER
        border = EmptyBorder(0, 0, 0, 0)
        SectivUi.styleCheck(this, theme)
    }

    override fun getTableCellRendererComponent(
        table: JTable,
        value: Any?,
        isSelected: Boolean,
        hasFocus: Boolean,
        row: Int,
        column: Int
    ): Component {
        background = if (isSelected) table.selectionBackground else table.background
        this.isSelected = value == true
        return this
    }
}

fun styleTable(table: JTable, theme: SectivTheme) = SectivUi.styleTable(table, theme)

fun scrollPane(view: Component, theme: SectivTheme): JScrollPane =
    JScrollPane(view).apply {
        SectivUi.styleScrollPane(this, theme)
    }

object Dialogs {
    fun error(parent: Component?, title: String, message: String) {
        JOptionPane.showMessageDialog(parent, message, title, JOptionPane.ERROR_MESSAGE)
    }

    fun info(parent: Component?, title: String, message: String) {
        JOptionPane.showMessageDialog(parent, message, title, JOptionPane.INFORMATION_MESSAGE)
    }

    fun confirm(parent: Component?, title: String, message: String): Boolean =
        JOptionPane.showConfirmDialog(
            parent,
            message,
            title,
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        ) == JOptionPane.YES_OPTION
}

/** Plain-text wrapping label. Never uses Swing HTML, so user/model content can never render as markup. */
class WrapLabel(
    text: String,
    labelFont: Font,
    labelColor: Color,
    private val wrapWidth: Int,
    private val center: Boolean = false
) : JComponent() {
    private var lines: List<String> = emptyList()

    init {
        font = labelFont
        foreground = labelColor
        isOpaque = false
        setText(text)
    }

    fun setText(text: String) {
        lines = wrapText(text, font, wrapWidth)
        revalidate()
        repaint()
    }

    override fun getPreferredSize(): Dimension {
        val fm = getFontMetrics(font)
        return Dimension(wrapWidth, lines.size.coerceAtLeast(1) * fm.height + 2)
    }

    override fun getMinimumSize(): Dimension = preferredSize

    override fun getMaximumSize(): Dimension = Dimension(Int.MAX_VALUE, preferredSize.height)

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
            g2.font = font
            g2.color = foreground
            val fm = g2.fontMetrics
            var y = fm.ascent
            for (line in lines) {
                val x = if (center) ((width - fm.stringWidth(line)) / 2).coerceAtLeast(0) else 0
                g2.drawString(line, x, y)
                y += fm.height
            }
        } finally {
            g2.dispose()
        }
    }

    companion object {
        private fun wrapText(text: String, font: Font, width: Int): List<String> {
            val fm = Toolkit.getDefaultToolkit().getFontMetrics(font)
            val maxWidth = width.coerceAtLeast(20)
            val out = mutableListOf<String>()
            for (paragraph in text.split('\n')) {
                if (paragraph.isEmpty()) {
                    out += ""
                    continue
                }
                val words = paragraph.split(' ').filter { it.isNotEmpty() }
                if (words.isEmpty()) {
                    out += ""
                    continue
                }
                val current = StringBuilder()
                for (word in words) {
                    val candidate = if (current.isEmpty()) word else "$current $word"
                    if (fm.stringWidth(candidate) <= maxWidth) {
                        if (current.isNotEmpty()) current.append(' ')
                        current.append(word)
                    } else {
                        if (current.isNotEmpty()) {
                            out += current.toString()
                            current.setLength(0)
                        }
                        var rest = word
                        while (fm.stringWidth(rest) > maxWidth) {
                            var cut = rest.length
                            while (cut > 1 && fm.stringWidth(rest.substring(0, cut)) > maxWidth) cut--
                            out += rest.substring(0, cut)
                            rest = rest.substring(cut)
                        }
                        if (rest.isNotEmpty()) current.append(rest)
                    }
                }
                if (current.isNotEmpty()) out += current.toString()
            }
            return out.ifEmpty { listOf("") }
        }
    }
}

fun htmlLabel(text: String, font: Font, color: Color, width: Int? = null): JComponent {
    return if (width != null) {
        WrapLabel(text, font, color, width)
    } else {
        JLabel(text).apply {
            this.font = font
            foreground = color
        }
    }
}

fun twoColumn(
    left: Component,
    right: Component,
    leftWeight: Double = 0.62,
    gap: Int = 14
): JPanel = JPanel(java.awt.GridBagLayout()).apply {
    isOpaque = false
    val c = java.awt.GridBagConstraints().apply {
        gridx = 0
        gridy = 0
        weightx = leftWeight
        weighty = 1.0
        fill = java.awt.GridBagConstraints.BOTH
        anchor = java.awt.GridBagConstraints.NORTHWEST
        insets = Insets(0, 0, 0, gap / 2)
    }
    add(left, c)
    c.gridx = 1
    c.weightx = 1.0 - leftWeight
    c.insets = Insets(0, gap / 2, 0, 0)
    add(right, c)
}

class ScrollableColumn : JPanel(), javax.swing.Scrollable {
    override fun getPreferredScrollableViewportSize(): Dimension = preferredSize

    override fun getScrollableUnitIncrement(
        visibleRect: java.awt.Rectangle,
        orientation: Int,
        direction: Int
    ): Int = 18

    override fun getScrollableBlockIncrement(
        visibleRect: java.awt.Rectangle,
        orientation: Int,
        direction: Int
    ): Int = if (orientation == SwingConstants.VERTICAL) visibleRect.height else visibleRect.width

    override fun getScrollableTracksViewportWidth(): Boolean = true

    override fun getScrollableTracksViewportHeight(): Boolean = false
}
