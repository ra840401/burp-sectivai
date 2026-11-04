package io.sectiv.burp.core

/**
 * Small text normalisation helpers used to keep raw model/provider content
 * from leaking HTML markup or control characters into UI labels.
 */
object Text {

    /** Strips HTML tags and collapses whitespace, then truncates. */
    fun plain(value: String?, max: Int = 400): String {
        if (value.isNullOrBlank()) return ""
        val stripped = value
            .replace(Regex("""(?s)<[^>]*>"""), " ")
            .replace(Regex("""[\r\n\t]+"""), " ")
            .replace(Regex("""\s+"""), " ")
            .trim()
        return stripped.take(max)
    }

    /** Truncates a message and strips control characters for display in a dialog or label. */
    fun safeMessage(value: String?, max: Int = 800): String =
        plain(value, max).ifBlank { "Unknown error" }
}
