package io.sectiv.burp.ui

import java.awt.Font
import java.io.InputStream

/**
 * Bundled fonts keep the UI identical on every Burp installation. Inter and
 * JetBrains Mono are both licensed under the SIL Open Font License.
 */
object SectivFonts {
    val regular: Font = load("/fonts/Inter-Regular.otf", "Inter", Font.PLAIN)
    val medium: Font = load("/fonts/Inter-Medium.otf", "Inter", Font.PLAIN)
    val semibold: Font = load("/fonts/Inter-SemiBold.otf", "Inter", Font.PLAIN)
    val bold: Font = load("/fonts/Inter-Bold.otf", "Inter", Font.BOLD)
    val mono: Font = load("/fonts/JetBrainsMono-400.ttf", "JetBrains Mono", Font.PLAIN)
    val monoMedium: Font = load("/fonts/JetBrainsMono-500.ttf", "JetBrains Mono", Font.PLAIN)

    fun regular(size: Float): Font = regular.deriveFont(size)
    fun medium(size: Float): Font = medium.deriveFont(size)
    fun semibold(size: Float): Font = semibold.deriveFont(size)
    fun bold(size: Float): Font = bold.deriveFont(size)
    fun mono(size: Float): Font = mono.deriveFont(size)
    fun monoMedium(size: Float): Font = monoMedium.deriveFont(size)

    private fun load(path: String, fallbackFamily: String, style: Int): Font {
        val stream: InputStream? = SectivFonts::class.java.getResourceAsStream(path)
        if (stream != null) {
            try {
                stream.use { return Font.createFont(Font.TRUETYPE_FONT, it) }
            } catch (_: Exception) {
                // Fall through to a system font.
            }
        }
        return Font(fallbackFamily, style, 12)
    }
}
