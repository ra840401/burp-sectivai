package io.sectiv.burp.core

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Serialises captured HTTP exchanges into a compact, redacted transcript for
 * the model. Header values for cookies and tokens are replaced with stable
 * identity markers so the model can still reason about BAC/IDOR without
 * receiving live credentials.
 */
object HttpTranscript {

    private const val REQUEST_CAP = 9000
    private val timeFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        .withZone(ZoneId.systemDefault())

    private val headerLine = Regex("""(?im)^(Cookie|Set-Cookie|Authorization|Proxy-Authorization)\s*:\s*(.*)$""")
    private val jsonSecret = Regex(
        """(?i)("(?:password|passwd|pwd|secret|client_secret|api_key|apikey|access_token|refresh_token|id_token|session_id|sessionid|auth_token|private_key)"\s*:\s*")(?:[^"\\]|\\.)*(")"""
    )
    private val paramSecret = Regex(
        """(?i)((?:^|[?&;\s"'])(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?id|sessionid|auth[_-]?token)\s*[=:]\s*)([^&;\s,}"']+)"""
    )
    private val jwt = Regex("""eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}""")

    fun render(
        exchange: CapturedExchange,
        settings: Settings,
        identities: IdentityPair,
        extraBudget: Int = Int.MAX_VALUE
    ): String {
        val request = clip(requestSection(exchange.requestRaw), REQUEST_CAP)
        val response = clip(responseSection(exchange.responseRaw), settings.maxResponseChars.coerceAtLeast(500))
        val header = buildString {
            append("=== EXCHANGE ===\n")
            append("Source: ").append(exchange.source).append('\n')
            append("Method: ").append(exchange.method).append('\n')
            append("URL: ").append(exchange.url).append('\n')
            append("Status: ").append(if (exchange.status > 0) exchange.status else "no response").append('\n')
            if (exchange.mime.isNotBlank()) append("MIME: ").append(exchange.mime).append('\n')
            append("Captured: ").append(timeFormat.format(Instant.ofEpochMilli(exchange.timestamp))).append('\n')
            append("--- REQUEST ---\n")
        }
        val rendered = buildString {
            append(header)
            append(redactIfNeeded(request, settings, identities))
            append("\n--- RESPONSE ---\n")
            append(redactIfNeeded(response, settings, identities))
            append("\n")
        }
        return clip(rendered, extraBudget)
    }

    fun redact(raw: String, identities: IdentityPair, maskSecrets: Boolean): String {
        if (raw.isEmpty() || !maskSecrets) return raw

        // Header-aware masking keeps cookie names and auth scheme visible while
        // removing the values. Identity values become stable placeholders.
        var output = headerLine.replace(raw) { match ->
            val name = match.groupValues[1]
            val value = match.groupValues[2].trim()
            val masked = when (name.lowercase()) {
                "cookie" -> maskCookie(value, identities)
                "set-cookie" -> maskSetCookie(value)
                "authorization", "proxy-authorization" -> maskAuthorization(value, identities)
                else -> value
            }
            "$name: $masked"
        }

        // Catch identity values that also appear in bodies or query strings.
        output = replaceIdentityLiterals(output, identities)

        output = jsonSecret.replace(output) { m -> m.groupValues[1] + "<redacted>" + m.groupValues[2] }
        output = paramSecret.replace(output) { m -> m.groupValues[1] + "<redacted>" }
        output = jwt.replace(output, "<redacted-jwt>")
        return output
    }

    fun clip(text: String, maxChars: Int): String {
        if (maxChars <= 0) return ""
        if (text.length <= maxChars) return text
        if (maxChars < 400) return text.take(maxChars) + "\n...[truncated]"
        val head = (maxChars * 0.78).toInt()
        val tail = (maxChars * 0.18).toInt()
        return text.take(head) +
            "\n...[truncated ${text.length - head - tail} chars]...\n" +
            text.takeLast(tail)
    }

    private fun redactIfNeeded(raw: String, settings: Settings, identities: IdentityPair): String =
        if (settings.maskSecrets) redact(raw, identities, true) else raw

    private fun requestSection(raw: String): String = raw.ifBlank { "<no request captured>" }

    private fun responseSection(raw: String): String {
        if (raw.isBlank()) return "<no response captured>"
        return raw
    }

    private fun maskCookie(value: String, identities: IdentityPair): String {
        val a = identities.a
        val b = identities.b
        val aCookies = cookieMap(a?.cookie)
        val bCookies = cookieMap(b?.cookie)
        val aValues = cookieValues(a?.cookie)
        val bValues = cookieValues(b?.cookie)

        if (value.isBlank()) return value
        val hasStructure = value.contains('=')
        if (!hasStructure) {
            val matchesA = value in aValues
            val matchesB = value in bValues
            return when {
                matchesA && !matchesB -> "[USER_A_COOKIE]"
                matchesB && !matchesA -> "[USER_B_COOKIE]"
                else -> "<redacted>"
            }
        }

        return value.split(';').joinToString(";") { segment ->
            val trimmed = segment.trim()
            val eq = trimmed.indexOf('=')
            if (eq <= 0) {
                trimmed
            } else {
                val name = trimmed.substring(0, eq).trim()
                val cookieValue = trimmed.substring(eq + 1).trim().removeSurrounding("\"")
                val matchesA = aCookies[name] == cookieValue || cookieValue in aValues
                val matchesB = bCookies[name] == cookieValue || cookieValue in bValues
                val marker = when {
                    matchesA && !matchesB -> "[USER_A_COOKIE]"
                    matchesB && !matchesA -> "[USER_B_COOKIE]"
                    else -> "<redacted>"
                }
                "$name=$marker"
            }
        }
    }

    private fun maskSetCookie(value: String): String {
        val first = value.substringBefore(';')
        val eq = first.indexOf('=')
        if (eq <= 0) return "<redacted>"
        val name = first.substring(0, eq).trim()
        val rest = value.substringAfter(';', "")
        return buildString {
            append(name).append("=<redacted>")
            if (rest.isNotBlank()) append(';').append(rest)
        }
    }

    private fun maskAuthorization(value: String, identities: IdentityPair): String {
        if (value.isBlank()) return value
        val normalized = stripScheme(value)
        val a = identities.a?.authorization
        val b = identities.b?.authorization
        val matchesA = !a.isNullOrBlank() && (value == a || normalized == stripScheme(a))
        val matchesB = !b.isNullOrBlank() && (value == b || normalized == stripScheme(b))
        return when {
            matchesA && !matchesB -> "[USER_A_AUTH]"
            matchesB && !matchesA -> "[USER_B_AUTH]"
            else -> "<redacted>"
        }
    }

    private fun replaceIdentityLiterals(text: String, identities: IdentityPair): String {
        var output = text
        for ((profile, label) in listOfNotNull(
            identities.a?.let { it to "A" },
            identities.b?.let { it to "B" }
        )) {
            profile.cookie?.takeIf { it.length >= 4 }?.let {
                output = output.replace(it, "[USER_${label}_COOKIE]")
            }
            profile.authorization?.takeIf { it.length >= 4 }?.let {
                output = output.replace(it, "[USER_${label}_AUTH]")
            }
        }
        return output
    }

    private fun stripScheme(value: String): String =
        value.trim().removePrefix("Bearer ").removePrefix("bearer ")
            .removePrefix("Token ").removePrefix("token ").trim()

    private fun cookieMap(raw: String?): Map<String, String> {
        if (raw.isNullOrBlank()) return emptyMap()
        return raw.split(';').mapNotNull { segment ->
            val trimmed = segment.trim()
            val eq = trimmed.indexOf('=')
            if (eq <= 0) null else trimmed.substring(0, eq).trim() to
                trimmed.substring(eq + 1).trim().removeSurrounding("\"")
        }.toMap()
    }

    private fun cookieValues(raw: String?): Set<String> {
        if (raw.isNullOrBlank()) return emptySet()
        if (!raw.contains('=')) return setOf(raw.trim())
        return cookieMap(raw).values.toSet()
    }
}
