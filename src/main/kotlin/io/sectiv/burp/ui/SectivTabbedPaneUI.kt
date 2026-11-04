package io.sectiv.burp.ui

import java.awt.Font
import java.awt.FontMetrics
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Insets
import java.awt.Rectangle
import java.awt.RenderingHints
import javax.swing.plaf.basic.BasicTabbedPaneUI

/**
 * A small, theme-aware tab UI. Burp's look-and-feel changes between releases
 * and the default Metal/FlatLaf insets clip the label at some font sizes, so
 * Sectiv paints its own tabs.
 */
class SectivTabbedPaneUI(private val theme: SectivTheme) : BasicTabbedPaneUI() {

    override fun getTabInsets(tabPlacement: Int, tabIndex: Int): Insets =
        Insets(8, 17, 8, 17)

    override fun getContentBorderInsets(tabPlacement: Int): Insets =
        Insets(4, 0, 0, 0)

    override fun paintContentBorder(g: Graphics, tabPlacement: Int, selectedIndex: Int) {
        // The panels themselves provide the surface; the default UI would draw
        // a light content border that breaks the dark workspace.
    }

    override fun paintTabBackground(
        g: Graphics,
        tabPlacement: Int,
        tabIndex: Int,
        x: Int,
        y: Int,
        w: Int,
        h: Int,
        isSelected: Boolean
    ) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = if (isSelected) theme.surface else theme.surfaceAlt
            g2.fillRoundRect(x + 2, y + 2, w - 4, h + 8, 12, 12)
            if (isSelected) {
                g2.color = theme.accent
                g2.fillRoundRect(x + 13, y, (w - 26).coerceAtLeast(8), 3, 3, 3)
            }
        } finally {
            g2.dispose()
        }
    }

    override fun paintTabBorder(
        g: Graphics,
        tabPlacement: Int,
        tabIndex: Int,
        x: Int,
        y: Int,
        w: Int,
        h: Int,
        isSelected: Boolean
    ) {
        // Flat tabs: no outline.
    }

    override fun paintFocusIndicator(
        g: Graphics,
        tabPlacement: Int,
        rects: Array<out Rectangle>?,
        tabIndex: Int,
        iconRect: Rectangle?,
        textRect: Rectangle?,
        isSelected: Boolean
    ) {
        // The selected tab already has an accent bar and a different surface.
    }

    override fun paintText(
        g: Graphics,
        tabPlacement: Int,
        font: Font,
        metrics: FontMetrics,
        tabIndex: Int,
        title: String,
        textRect: Rectangle,
        isSelected: Boolean
    ) {
        if (title.isEmpty()) return
        val g2 = g.create() as Graphics2D
        try {
            g2.font = font
            g2.color = if (isSelected) theme.text else theme.muted
            val x = textRect.x + (textRect.width - metrics.stringWidth(title)) / 2
            val y = textRect.y + (textRect.height - metrics.height) / 2 + metrics.ascent
            g2.drawString(title, x, y)
        } finally {
            g2.dispose()
        }
    }
}
