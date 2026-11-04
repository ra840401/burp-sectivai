package io.sectiv.burp.ui

import burp.api.montoya.MontoyaApi
import io.sectiv.burp.core.Severity
import java.awt.Color

/**
 * Design tokens for the Sectiv dark workspace. The palette is derived from the
 * product mark: near-black background, white type and the orange signal dot.
 */
class SectivTheme(api: MontoyaApi) {
    val dark: Boolean = true

    val background = Color(0x0B, 0x0F, 0x12)
    val backgroundDeep = Color(0x08, 0x0B, 0x0D)
    val surface = Color(0x12, 0x17, 0x1C)
    val surfaceAlt = Color(0x16, 0x1D, 0x23)
    val surfaceRaised = Color(0x1B, 0x24, 0x2C)
    val surfaceHover = Color(0x20, 0x2A, 0x33)
    val border = Color(0x24, 0x2E, 0x37)
    val borderSoft = Color(0x1B, 0x23, 0x2A)
    val borderStrong = Color(0x33, 0x40, 0x4B)
    val text = Color(0xF4, 0xF6, 0xF5)
    val textSoft = Color(0xD7, 0xDE, 0xE3)
    val muted = Color(0x8D, 0x99, 0xA4)
    val faint = Color(0x5D, 0x69, 0x73)
    val accent = Color(0xF4, 0x78, 0x32)
    val accentHover = Color(0xFF, 0x8A, 0x4C)
    val accentSoft = Color(0x2A, 0x1C, 0x14)
    val accentInk = Color(0x1D, 0x10, 0x08)
    val danger = Color(0xFF, 0x5D, 0x5D)
    val success = Color(0x4A, 0xDE, 0x80)
    val warning = Color(0xF4, 0xC9, 0x5D)
    val info = Color(0x91, 0xA0, 0xAD)
    val codeBackground = Color(0x09, 0x0D, 0x10)
    val codeText = Color(0xC8, 0xD4, 0xDF)
    val tableSelection = Color(0x1D, 0x26, 0x2E)

    val base = SectivFonts.regular(13f)
    val baseMedium = SectivFonts.medium(13f)
    val small = SectivFonts.regular(11f)
    val smallMedium = SectivFonts.medium(11f)
    val tiny = SectivFonts.regular(10f)
    val eyebrow = SectivFonts.monoMedium(10f)
    val h1 = SectivFonts.semibold(26f)
    val h2 = SectivFonts.semibold(18f)
    val h3 = SectivFonts.semibold(12f)
    val badge = SectivFonts.semibold(9.5f)
    val number = SectivFonts.bold(31f)
    val mono = SectivFonts.mono(11.5f)
    val monoSmall = SectivFonts.mono(10.5f)
    val monoMedium = SectivFonts.monoMedium(10.5f)

    fun severityBg(severity: Severity): Color = when (severity) {
        Severity.CRITICAL -> Color(0x2A, 0x18, 0x1A)
        Severity.HIGH -> Color(0x2A, 0x20, 0x16)
        Severity.MEDIUM -> Color(0x2A, 0x25, 0x15)
        Severity.LOW -> Color(0x15, 0x27, 0x1D)
        Severity.INFO -> Color(0x1B, 0x23, 0x29)
    }

    fun severityFg(severity: Severity): Color = when (severity) {
        Severity.CRITICAL -> Color(0xFF, 0x85, 0x85)
        Severity.HIGH -> Color(0xFF, 0xB1, 0x6A)
        Severity.MEDIUM -> Color(0xF5, 0xD4, 0x7C)
        Severity.LOW -> Color(0x72, 0xE9, 0xA0)
        Severity.INFO -> Color(0xA5, 0xB3, 0xC0)
    }

    fun severityDot(severity: Severity): Color = when (severity) {
        Severity.CRITICAL -> Color(0xFF, 0x5D, 0x5D)
        Severity.HIGH -> Color(0xFF, 0x9F, 0x43)
        Severity.MEDIUM -> Color(0xF4, 0xC9, 0x5D)
        Severity.LOW -> Color(0x4A, 0xDE, 0x80)
        Severity.INFO -> Color(0x91, 0xA0, 0xAD)
    }

    fun severityBorder(severity: Severity): Color = when (severity) {
        Severity.CRITICAL -> Color(0x5A, 0x2B, 0x30)
        Severity.HIGH -> Color(0x5A, 0x3E, 0x26)
        Severity.MEDIUM -> Color(0x55, 0x4A, 0x24)
        Severity.LOW -> Color(0x24, 0x4C, 0x34)
        Severity.INFO -> Color(0x33, 0x40, 0x4A)
    }
}
