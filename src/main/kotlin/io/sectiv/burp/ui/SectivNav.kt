package io.sectiv.burp.ui

import java.awt.BasicStroke
import java.awt.CardLayout
import java.awt.Color
import java.awt.Cursor
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BorderFactory
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.border.EmptyBorder

/**
 * The top navigation in the redesign is a compact pill bar rather than a
 * classic JTabbedPane. Keeping our own bar also avoids Burp LAF tab clipping.
 */
class SectivNavHost(private val theme: SectivTheme) {

    private val items = mutableListOf<NavItem>()
    private val cards = CardLayout()
    private val content = JPanel(cards).apply { isOpaque = false }

    val navBar: JPanel = RoundedPanel(theme, theme.surface, theme.borderSoft, 12).apply {
        layout = FlowLayout(FlowLayout.LEFT, 3, 0)
        border = EmptyBorder(4, 4, 4, 4)
    }

    val contentComponent: JComponent
        get() = content

    private var selected = -1

    fun addTab(label: String, component: JComponent) {
        val index = items.size
        val item = NavItem(label, theme) { selectedIndex = index }
        items += item
        navBar.add(item)
        content.add(component, index.toString())
        if (index == 0) selectedIndex = 0
        navBar.revalidate()
        navBar.repaint()
    }

    var selectedIndex: Int
        get() = selected
        set(value) {
            if (value !in items.indices) return
            selected = value
            items.forEachIndexed { index, item -> item.setActive(index == value) }
            cards.show(content, value.toString())
        }

    fun setBadgeAt(index: Int, badge: String?) {
        items.getOrNull(index)?.setBadge(badge)
    }

    private class NavItem(
        private val label: String,
        private val theme: SectivTheme,
        onClick: () -> Unit
    ) : JComponent() {
        private var active = false
        private var hover = false
        private var badge: String? = null

        init {
            isOpaque = false
            updateSize()
            cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
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

        fun setActive(value: Boolean) {
            active = value
            updateSize()
            repaint()
        }

        fun setBadge(value: String?) {
            badge = value
            updateSize()
            repaint()
        }

        private fun updateSize() {
            val fm = getFontMetrics(SectivFonts.medium(12.5f))
            val buttonWidth = fm.stringWidth(label) + 26
            val badgeWidth = if (badge != null) 19 else 0
            val activeDot = if (active) 10 else 0
            preferredSize = Dimension(buttonWidth + badgeWidth + activeDot, 32)
            revalidate()
        }

        override fun paintComponent(g: Graphics) {
            val g2 = g.create() as Graphics2D
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                if (active) {
                    g2.color = theme.surfaceRaised
                    g2.fillRoundRect(0, 0, width - 1, height - 1, 9, 9)
                    g2.color = theme.border
                    g2.stroke = BasicStroke(1f)
                    g2.drawRoundRect(0, 0, width - 1, height - 1, 9, 9)
                } else if (hover) {
                    g2.color = withAlpha(Color.WHITE, 8)
                    g2.fillRoundRect(0, 0, width - 1, height - 1, 9, 9)
                }

                g2.font = SectivFonts.medium(12.5f)
                g2.color = if (active) theme.text else theme.muted
                val metrics = g2.fontMetrics
                var x = 13
                g2.drawString(label, x, (height - metrics.height) / 2 + metrics.ascent)
                x += metrics.stringWidth(label) + 7

                if (badge != null) {
                    val bm = g2.fontMetrics
                    g2.font = SectivFonts.monoMedium(9f)
                    val bw = g2.fontMetrics.stringWidth(badge!!) + 9
                    g2.color = withAlpha(Color.WHITE, 12)
                    g2.fillRoundRect(x, (height - 17) / 2, bw, 17, 5, 5)
                    g2.color = theme.muted
                    g2.drawString(badge, x + 4, (height - bm.height) / 2 + bm.ascent - 1)
                    x += bw + 6
                }

                if (active) {
                    g2.color = theme.accent
                    g2.fillOval(x + 1, height / 2 - 2, 4, 4)
                }
            } finally {
                g2.dispose()
            }
        }
    }
}
