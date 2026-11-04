package io.sectiv.burp.core

/**
 * Best-effort parser for the free-text identity box. It understands the
 * template inserted by the UI plus a few common one-line variants, because
 * testers paste notes from all sorts of places.
 */
data class IdentityProfile(
    val label: String,
    val email: String? = null,
    val cookie: String? = null,
    val authorization: String? = null,
    val username: String? = null
) {
    val hasCredentials: Boolean
        get() = !cookie.isNullOrBlank() || !authorization.isNullOrBlank()

    val hasAny: Boolean
        get() = hasCredentials || !email.isNullOrBlank() || !username.isNullOrBlank()

    fun merge(other: IdentityProfile): IdentityProfile = IdentityProfile(
        label = label,
        email = other.email ?: email,
        cookie = other.cookie ?: cookie,
        authorization = other.authorization ?: authorization,
        username = other.username ?: username
    )

    fun describe(): String {
        val parts = buildList {
            if (!email.isNullOrBlank()) add("email")
            if (!cookie.isNullOrBlank()) add("cookie")
            if (!authorization.isNullOrBlank()) add("auth header")
            if (!username.isNullOrBlank()) add("username")
        }
        return if (parts.isEmpty()) "no credentials" else parts.joinToString(", ")
    }
}

data class IdentityPair(
    val a: IdentityProfile?,
    val b: IdentityProfile?
) {
    val hasCompleteCredentials: Boolean
        get() = a?.hasCredentials == true && b?.hasCredentials == true

    val hasAnyIdentity: Boolean
        get() = a?.hasAny == true || b?.hasAny == true

    /** True when both profiles share at least one header type that can be swapped. */
    val swappable: Boolean
        get() {
            val left = a ?: return false
            val right = b ?: return false
            val cookieSwap = !left.cookie.isNullOrBlank() &&
                !right.cookie.isNullOrBlank() && left.cookie != right.cookie
            val authSwap = !left.authorization.isNullOrBlank() &&
                !right.authorization.isNullOrBlank() && left.authorization != right.authorization
            return cookieSwap || authSwap
        }

    fun summary(): String {
        if (a == null && b == null) return "No identities detected"
        return listOfNotNull(
            a?.let { "A: ${it.describe()}" },
            b?.let { "B: ${it.describe()}" }
        ).joinToString("  |  ")
    }

    companion object {
        val EMPTY = IdentityPair(null, null)
    }
}

object IdentityContextParser {

    val TEMPLATE: String = """
        User A
          email: alice@example.com
          Cookie: session=PASTE_USER_A_SESSION
          Authorization: Bearer PASTE_USER_A_TOKEN

        User B
          email: bob@example.com
          Cookie: session=PASTE_USER_B_SESSION
          Authorization: Bearer PASTE_USER_B_TOKEN
    """.trimIndent()

    private val inlineHeader = Regex(
        """(?i)\buser\s*([ab])\b\s*(?:'s)?\s*(?:session\s+)?(cookie|authorization|auth|bearer|token|email|e-mail)\s*(?:header)?\s*(?:is|:|=)\s*([^\r\n]+)"""
    )
    private val inlineEmail = Regex(
        """(?i)\buser\s*([ab])\b\s*(?:is\s*)?(?:a\s*)?user\s*(?:with\s*)?(?:the\s*)?email\s*(?:is|:|=)?\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"""
    )
    private val userHeader = Regex(
        """(?i)^\s*(?:user|account|identity)\s*([ab])\b\s*(?:\([^)]*\))?\s*[:\-]\s*(.*)$"""
    )
    private val userHeaderBare = Regex(
        """(?i)^\s*(?:user|account|identity)\s*([ab])\b\s*(?:\([^)]*\))?\s*$"""
    )
    private val shortHeader = Regex("""^\s*([AB])\s*[:\-]\s*(.*)$""")
    private val keyValue = Regex(
        """(?i)^\s*(?:[-*•]\s*)?(cookie|authorization|auth|bearer|token|email|e-mail|username|role)\s*[:=]\s*(.*)$"""
    )
    private val emailOnly = Regex("""^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$""")

    fun parse(text: String): IdentityPair {
        if (text.isBlank()) return IdentityPair.EMPTY
        val profiles = mutableMapOf<String, IdentityProfile>()

        fun merge(profile: IdentityProfile) {
            val label = profile.label.uppercase()
            val existing = profiles[label]
            profiles[label] = if (existing == null) profile.copy(label = label) else existing.merge(profile)
        }

        // One-line forms: "User A cookie is: session=..." / "User A is a user with email ...".
        for (match in inlineHeader.findAll(text)) {
            val label = match.groupValues[1].uppercase()
            val key = match.groupValues[2].lowercase()
            val value = cleanValue(match.groupValues[3])
            if (value.isBlank()) continue
            merge(
                when (key) {
                    "cookie" -> IdentityProfile(label, cookie = value)
                    "email", "e-mail" -> IdentityProfile(label, email = value.substringBefore(',').trim())
                    else -> IdentityProfile(label, authorization = normalizeAuthorization(value))
                }
            )
        }
        for (match in inlineEmail.findAll(text)) {
            merge(IdentityProfile(match.groupValues[1].uppercase(), email = cleanValue(match.groupValues[2])))
        }

        // Block forms, including the UI template.
        var block: IdentityProfile? = null
        for (rawLine in text.lineSequence()) {
            val line = rawLine.trim().trimStart('-', '*', '•', '>').trim()
            if (line.isEmpty()) continue

            val header = userHeader.find(line)
            if (header != null) {
                block?.let { merge(it) }
                val label = header.groupValues[1].uppercase()
                val rest = header.groupValues[2].trim()
                block = IdentityProfile(label)
                if (rest.isNotEmpty()) {
                    block = applyField(block!!, rest)
                }
                continue
            }
            if (userHeaderBare.matches(line)) {
                block?.let { merge(it) }
                block = IdentityProfile(userHeaderBare.find(line)!!.groupValues[1].uppercase())
                continue
            }
            val short = shortHeader.find(line)
            if (short != null && !line.lowercase().startsWith("http")) {
                block?.let { merge(it) }
                block = IdentityProfile(short.groupValues[1])
                val rest = short.groupValues[2].trim()
                if (rest.isNotEmpty()) block = applyField(block!!, rest)
                continue
            }

            val current = block ?: continue
            val kv = keyValue.find(line)
            if (kv != null) {
                val key = kv.groupValues[1].lowercase()
                val value = cleanValue(kv.groupValues[2])
                block = when (key) {
                    "cookie" -> current.copy(cookie = value)
                    "email", "e-mail" -> current.copy(email = value)
                    "authorization", "auth", "bearer", "token" ->
                        current.copy(authorization = normalizeAuthorization(value))
                    "username" -> current.copy(username = value)
                    else -> current
                }
                continue
            }
            if (emailOnly.matches(line) && current.email.isNullOrBlank()) {
                block = current.copy(email = line)
            }
        }
        block?.let { merge(it) }

        val a = profiles["A"]?.let(::sanitize)
        val b = profiles["B"]?.let(::sanitize)
        return IdentityPair(a, b)
    }

    private fun sanitize(profile: IdentityProfile): IdentityProfile = profile.copy(
        email = profile.email?.takeUnless(::isPlaceholder),
        cookie = profile.cookie?.takeUnless(::isPlaceholder),
        authorization = profile.authorization?.takeUnless(::isPlaceholder),
        username = profile.username?.takeUnless(::isPlaceholder)
    )

    /** Template values such as PASTE_USER_A_TOKEN must never be used as credentials. */
    fun isPlaceholder(value: String): Boolean {
        val v = value.trim()
        if (v.isBlank()) return true
        val upper = v.uppercase()
        return upper.contains("PASTE") ||
            upper.contains("YOUR_") ||
            upper.contains("REPLACE_ME") ||
            upper.contains("CHANGEME") ||
            (v.startsWith("<") && v.endsWith(">"))
    }

    private fun applyField(profile: IdentityProfile, text: String): IdentityProfile {
        val value = text.trim()
        if (emailOnly.matches(value)) return profile.copy(email = value)
        val kv = keyValue.find(value)
        if (kv != null) {
            val key = kv.groupValues[1].lowercase()
            val v = cleanValue(kv.groupValues[2])
            return when (key) {
                "cookie" -> profile.copy(cookie = v)
                "email", "e-mail" -> profile.copy(email = v)
                "authorization", "auth", "bearer", "token" -> profile.copy(authorization = normalizeAuthorization(v))
                "username" -> profile.copy(username = v)
                else -> profile
            }
        }
        val auth = Regex("""(?i)^(cookie|authorization|auth|bearer|token|email)\s*(?:is)?\s*[:=]?\s+(.+)$""").find(value)
        if (auth != null) {
            val v = cleanValue(auth.groupValues[2])
            return when (auth.groupValues[1].lowercase()) {
                "cookie" -> profile.copy(cookie = v)
                "email" -> profile.copy(email = v)
                else -> profile.copy(authorization = normalizeAuthorization(v))
            }
        }
        return profile
    }

    private fun cleanValue(value: String): String =
        value.trim()
            .removePrefix(":")
            .removePrefix("=")
            .trim()
            .removeSurrounding("`")
            .removeSurrounding("\"")
            .trim()
            .removeSuffix(",")

    private fun normalizeAuthorization(value: String): String {
        val trimmed = cleanValue(value)
        if (trimmed.isBlank()) return trimmed
        if (trimmed.startsWith("Bearer ", true) ||
            trimmed.startsWith("Basic ", true) ||
            trimmed.startsWith("Token ", true) ||
            trimmed.startsWith("Digest ", true)
        ) return trimmed
        return "Bearer $trimmed"
    }
}
