package io.sectiv.burp.scan

import io.sectiv.burp.core.CapturedExchange
import io.sectiv.burp.core.Confidence
import io.sectiv.burp.core.IdentityPair
import io.sectiv.burp.core.IdentityProfile

data class SwapRequest(
    val raw: String,
    val replaced: List<String>
)

data class SwapVerdict(
    val vulnerable: Boolean,
    val confidence: Confidence,
    val similarity: Double,
    val markerSeen: Boolean,
    val reason: String
)

/**
 * Deterministic identity-swap verification: replay the captured request with
 * User A's session material replaced by User B's, then compare the response
 * with the original. This turns the AI's BAC/IDOR hypotheses into something
 * the tester can actually see, without letting the model craft arbitrary
 * requests.
 */
object IdentitySwap {

    private val cookieLine = Regex("""(?im)^(Cookie\s*:\s*)(.+)$""")
    private val credentialCookieName = Regex("""(?i)(session|sess|sid|token|auth|jwt|remember|login|access|refresh)""")
    private val authorizationLine = Regex("""(?im)^(Authorization\s*:\s*)(.+)$""")

    private val negativePhrases = listOf(
        "unauthorized",
        "access denied",
        "permission denied",
        "not authorized",
        "not permitted",
        "forbidden",
        "authentication required",
        "session expired",
        "invalid session",
        "invalid token",
        "please log in",
        "please login",
        "please sign in",
        "login required",
        "sign in to continue"
    )

    fun buildRequest(originalRaw: String, identities: IdentityPair): SwapRequest? {
        val a = identities.a ?: return null
        val b = identities.b ?: return null
        val separator = when {
            originalRaw.contains("\r\n\r\n") -> "\r\n\r\n"
            originalRaw.contains("\n\n") -> "\n\n"
            else -> ""
        }
        val head: String
        val body: String
        if (separator.isEmpty()) {
            head = originalRaw
            body = ""
        } else {
            val index = originalRaw.indexOf(separator)
            head = originalRaw.substring(0, index)
            body = originalRaw.substring(index + separator.length)
        }

        var newHead = head
        val replaced = mutableListOf<String>()
        var cookieSwapped = false
        var authSwapped = false

        newHead = cookieLine.replace(newHead) { match ->
            val prefix = match.groupValues[1]
            val value = match.groupValues[2].trim()
            val swapped = swapCookie(value, a, b)
            if (swapped != null) {
                cookieSwapped = true
                replaced += "Cookie"
                "$prefix$swapped"
            } else {
                match.value
            }
        }

        newHead = authorizationLine.replace(newHead) { match ->
            val prefix = match.groupValues[1]
            val value = match.groupValues[2].trim()
            val swapped = swapAuthorization(value, a, b)
            if (swapped != null) {
                authSwapped = true
                replaced += "Authorization"
                "$prefix$swapped"
            } else {
                match.value
            }
        }

        // Do not leave the other credential mechanism from User A in the
        // request. If User B has a value, use it; otherwise remove the header.
        if (cookieSwapped) {
            if (!authSwapped && headerValue(newHead, "Authorization") != null) {
                if (b.authorization.isNullOrBlank()) {
                    newHead = removeHeader(newHead, "Authorization")
                    replaced += "Authorization (removed)"
                } else {
                    newHead = setHeader(newHead, "Authorization", b.authorization!!)
                    replaced += "Authorization"
                }
            }
        }
        if (authSwapped) {
            if (!cookieSwapped && headerValue(newHead, "Cookie") != null) {
                if (b.cookie.isNullOrBlank()) {
                    newHead = removeHeader(newHead, "Cookie")
                    replaced += "Cookie (removed)"
                } else {
                    newHead = setHeader(newHead, "Cookie", b.cookie!!)
                    replaced += "Cookie"
                }
            }
        }

        val output = if (separator.isEmpty()) newHead else newHead + separator + body
        if (replaced.isEmpty() || output == originalRaw) return null
        return SwapRequest(output, replaced.distinct())
    }

    private fun headerValue(head: String, name: String): String? =
        Regex("""(?im)^${Regex.escape(name)}\s*:\s*(.+)$""")
            .find(head)?.groupValues?.get(1)?.trim()

    private fun removeHeader(head: String, name: String): String {
        val pattern = Regex("""(?im)^${Regex.escape(name)}\s*:.*(?:\r?\n|$)""")
        return pattern.replace(head, "").trimEnd('\r', '\n')
    }

    private fun setHeader(head: String, name: String, value: String): String {
        val lineEnding = if (head.contains("\r\n")) "\r\n" else "\n"
        val cleaned = removeHeader(head, name).trimEnd('\r', '\n')
        return cleaned + lineEnding + name + ": " + value
    }

    fun evaluate(
        original: CapturedExchange,
        testStatus: Int,
        testBody: String,
        identities: IdentityPair
    ): SwapVerdict {
        if (original.status !in 200..299) {
            return SwapVerdict(false, Confidence.TENTATIVE, 0.0, false, "Original request did not return a success response.")
        }
        if (testStatus == 401 || testStatus == 403 || testStatus == 407) {
            return SwapVerdict(false, Confidence.TENTATIVE, 0.0, false, "Server rejected the request with HTTP $testStatus, so the endpoint enforces authorization.")
        }
        if (testStatus !in 200..299) {
            return SwapVerdict(false, Confidence.TENTATIVE, 0.0, false, "Request as User B returned HTTP $testStatus rather than a success response.")
        }

        val originalBody = bodyOf(original.responseRaw)
        val testLower = testBody.lowercase()
        val negative = negativePhrases.firstOrNull { testLower.contains(it) }
        if (negative != null && testBody.length < originalBody.length * 0.6) {
            return SwapVerdict(false, Confidence.TENTATIVE, 0.0, false, "The response looks like an authorization error (\"$negative\").")
        }

        if (testBody.isBlank() || originalBody.isBlank()) {
            return SwapVerdict(false, Confidence.TENTATIVE, 0.0, false, "One of the responses had an empty body, so the result cannot be compared.")
        }

        val similarity = similarity(originalBody, testBody)
        val lengthRatio = testBody.length.toDouble() / originalBody.length.coerceAtLeast(1)
        val marker = identityMarker(identities.a)?.let { testLower.contains(it.lowercase()) } ?: false

        if (lengthRatio < 0.35) {
            return SwapVerdict(false, Confidence.TENTATIVE, similarity, marker, "The response as User B was much smaller than the original (${(lengthRatio * 100).toInt()}%).")
        }
        if (similarity < 0.72) {
            return SwapVerdict(false, Confidence.TENTATIVE, similarity, marker, "The responses differ substantially; User B does not appear to receive User A's data.")
        }

        val confidence = when {
            marker && similarity >= 0.80 -> Confidence.CERTAIN
            marker || similarity >= 0.92 -> Confidence.FIRM
            else -> Confidence.TENTATIVE
        }
        val reason = buildString {
            append("User B received HTTP $testStatus with ")
            append((similarity * 100).toInt()).append("% response similarity to User A's response")
            if (marker) append("; User A's identifier was present in the response")
            append(".")
            if (!marker) append(" Review manually to rule out a public or shared resource.")
        }
        return SwapVerdict(true, confidence, similarity, marker, reason)
    }

    private fun identityMarker(profile: IdentityProfile?): String? {
        if (profile == null) return null
        return profile.email?.takeIf { it.isNotBlank() }
            ?: profile.username?.takeIf { it.isNotBlank() }
    }

    private fun swapCookie(value: String, a: IdentityProfile, b: IdentityProfile): String? {
        val aCookie = a.cookie?.trim() ?: return null
        val bCookie = b.cookie?.trim() ?: return null
        if (aCookie == bCookie) return null

        if (value == aCookie) return bCookie

        val aMap = cookieMap(aCookie)
        val bMap = cookieMap(bCookie)
        if (aMap.isEmpty() || bMap.isEmpty()) return null

        var changed = false
        val swapped = value.split(';').joinToString(";") { segment ->
            val trimmed = segment.trim()
            val eq = trimmed.indexOf('=')
            if (eq <= 0) {
                trimmed
            } else {
                val name = trimmed.substring(0, eq).trim()
                val cookieValue = trimmed.substring(eq + 1).trim().removeSurrounding("\"")
                val bValue = bMap[name]
                val credentialName = credentialCookieName.containsMatchIn(name)
                if (credentialName && aMap[name] == cookieValue && bValue != null && bValue != cookieValue) {
                    changed = true
                    "$name=$bValue"
                } else {
                    trimmed
                }
            }
        }
        return if (changed) swapped else null
    }

    private fun swapAuthorization(value: String, a: IdentityProfile, b: IdentityProfile): String? {
        val aAuth = a.authorization?.trim() ?: return null
        val bAuth = b.authorization?.trim() ?: return null
        if (aAuth == bAuth) return null
        val valueToken = stripScheme(value)
        val aToken = stripScheme(aAuth)
        return if (value == aAuth || valueToken == aToken) bAuth else null
    }

    private fun stripScheme(value: String): String =
        value.trim().removePrefix("Bearer ").removePrefix("bearer ")
            .removePrefix("Token ").removePrefix("token ").trim()

    private fun cookieMap(raw: String): Map<String, String> =
        raw.split(';').mapNotNull { segment ->
            val trimmed = segment.trim()
            val eq = trimmed.indexOf('=')
            if (eq <= 0) null else trimmed.substring(0, eq).trim() to
                trimmed.substring(eq + 1).trim().removeSurrounding("\"")
        }.toMap()

    fun bodyOf(raw: String): String {
        if (raw.isBlank()) return ""
        val crlf = raw.indexOf("\r\n\r\n")
        if (crlf >= 0) return raw.substring(crlf + 4)
        val lf = raw.indexOf("\n\n")
        if (lf >= 0) return raw.substring(lf + 2)
        return raw
    }

    /** Token Jaccard plus identical-line ratio; robust to reordered JSON keys. */
    fun similarity(left: String, right: String): Double {
        if (left == right) return 1.0
        val leftTokens = tokens(left)
        val rightTokens = tokens(right)
        if (leftTokens.isEmpty() || rightTokens.isEmpty()) return 0.0
        val intersection = leftTokens.count { it in rightTokens }
        val union = leftTokens.size + rightTokens.size - intersection
        val jaccard = if (union == 0) 0.0 else intersection.toDouble() / union

        val leftLines = lines(left)
        val rightLines = lines(right)
        val lineRatio = if (leftLines.isEmpty() || rightLines.isEmpty()) 0.0 else {
            val common = leftLines.count { it in rightLines }
            common.toDouble() / maxOf(leftLines.size, rightLines.size)
        }
        return maxOf(jaccard, lineRatio)
    }

    private fun tokens(text: String): Set<String> {
        val set = LinkedHashSet<String>()
        var i = 0
        val current = StringBuilder()
        while (i < text.length && set.size < 6000) {
            val c = text[i]
            if (c.isLetterOrDigit()) {
                current.append(c.lowercaseChar())
            } else if (current.isNotEmpty()) {
                if (current.length >= 2) set += current.toString()
                current.setLength(0)
            }
            i++
        }
        if (current.length >= 2 && set.size < 6000) set += current.toString()
        return set
    }

    private fun lines(text: String): Set<String> {
        return text.lineSequence()
            .map { it.trim() }
            .filter { it.length >= 4 }
            .take(800)
            .toSet()
    }
}
