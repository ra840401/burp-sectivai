package io.sectiv.burp

import io.sectiv.burp.core.HttpTranscript
import io.sectiv.burp.core.IdentityPair
import io.sectiv.burp.core.IdentityProfile
import io.sectiv.burp.core.Settings
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HttpTranscriptTest {

    private val identities = IdentityPair(
        a = IdentityProfile(
            label = "A",
            email = "alice@example.com",
            cookie = "session=aaa; theme=light",
            authorization = "Bearer AAA"
        ),
        b = IdentityProfile(
            label = "B",
            email = "bob@example.com",
            cookie = "session=bbb; theme=dark",
            authorization = "Bearer BBB"
        )
    )

    private val rawRequest = buildString {
        append("POST /api/account HTTP/1.1\r\n")
        append("Host: app.example.com\r\n")
        append("Cookie: session=aaa; theme=light\r\n")
        append("Authorization: Bearer AAA\r\n")
        append("Content-Type: application/json\r\n\r\n")
        append("{\"password\":\"hunter2\",\"email\":\"alice@example.com\",\"api_key\":\"sk-live-secret\",\"note\":\"session=aaa; theme=light\"}")
    }

    @Test
    fun `masks cookies but keeps identity markers and names`() {
        val redacted = HttpTranscript.redact(rawRequest, identities, true)
        assertTrue(redacted.contains("session=[USER_A_COOKIE]"))
        assertTrue(redacted.contains("theme=[USER_A_COOKIE]"))
        assertFalse(redacted.contains("session=aaa"))
        assertTrue(redacted.contains("Authorization: [USER_A_AUTH]"))
    }

    @Test
    fun `masks passwords api keys and identity literals in bodies`() {
        val redacted = HttpTranscript.redact(rawRequest, identities, true)
        assertFalse(redacted.contains("hunter2"))
        assertFalse(redacted.contains("sk-live-secret"))
        assertTrue(redacted.contains("<redacted>"))
        assertTrue(redacted.contains("[USER_A_COOKIE]"))
        // Emails are intentionally retained: they are the primary BOLA/IDOR signal.
        assertTrue(redacted.contains("alice@example.com"))
    }

    @Test
    fun `masking can be disabled`() {
        val redacted = HttpTranscript.redact(rawRequest, identities, false)
        assertTrue(redacted.contains("session=aaa"))
        assertTrue(redacted.contains("hunter2"))
    }

    @Test
    fun `renders metadata and clips oversized response`() {
        val exchange = TestData.exchange(
            request = rawRequest,
            response = "HTTP/1.1 200 OK\r\n\r\n" + "A".repeat(20_000)
        )
        val rendered = HttpTranscript.render(
            exchange,
            Settings(maxResponseChars = 1000),
            identities
        )
        assertTrue(rendered.contains("Method: GET"))
        assertTrue(rendered.contains("https://app.example.com/api/users/1"))
        assertTrue(rendered.contains("truncated"))
        assertTrue(rendered.length < 20_000)
    }

    @Test
    fun `clip keeps head and tail`() {
        val text = "HEAD" + "x".repeat(10_000) + "TAIL"
        val clipped = HttpTranscript.clip(text, 1000)
        assertTrue(clipped.startsWith("HEAD"))
        assertTrue(clipped.endsWith("TAIL"))
        assertTrue(clipped.contains("truncated"))
    }
}
