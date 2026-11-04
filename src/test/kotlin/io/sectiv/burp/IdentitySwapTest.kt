package io.sectiv.burp

import io.sectiv.burp.core.Confidence
import io.sectiv.burp.core.IdentityPair
import io.sectiv.burp.core.IdentityProfile
import io.sectiv.burp.scan.IdentitySwap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class IdentitySwapTest {

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

    private val originalRequest = "GET /api/account/1 HTTP/1.1\r\n" +
        "Host: app.example.com\r\n" +
        "Cookie: session=aaa; theme=light\r\n" +
        "Authorization: Bearer AAA\r\n\r\n"

    @Test
    fun `builds a request with the second identity`() {
        val swap = assertNotNull(IdentitySwap.buildRequest(originalRequest, identities))
        assertTrue(swap.raw.contains("session=bbb"))
        assertTrue(swap.raw.contains("theme=dark"))
        assertTrue(swap.raw.contains("Authorization: Bearer BBB"))
        assertFalse(swap.raw.contains("session=aaa"))
        assertFalse(swap.raw.contains("Bearer AAA"))
        assertTrue(swap.replaced.contains("Cookie"))
        assertTrue(swap.replaced.contains("Authorization"))
    }

    @Test
    fun `removes user a authorization when user b only has a cookie`() {
        val bCookieOnly = IdentityPair(
            a = identities.a,
            b = IdentityProfile(label = "B", email = "bob@example.com", cookie = "session=bbb; theme=dark")
        )
        val swap = assertNotNull(IdentitySwap.buildRequest(originalRequest, bCookieOnly))
        assertTrue(swap.raw.contains("session=bbb"))
        assertFalse(swap.raw.contains("Authorization: Bearer AAA"))
        assertFalse(swap.raw.contains("Bearer AAA"))
    }

    @Test
    fun `does not build a request when no credential matches`() {
        val text = originalRequest.replace("session=aaa", "session=zzz")
            .replace("Bearer AAA", "Bearer ZZZ")
        val swap = IdentitySwap.buildRequest(text, identities)
        kotlin.test.assertNull(swap)
    }

    @Test
    fun `flags an identical success response containing user a data`() {
        val exchange = TestData.exchange(
            request = originalRequest,
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"email\":\"alice@example.com\",\"account\":\"1\",\"name\":\"Alice\"}"
        )
        val verdict = IdentitySwap.evaluate(
            exchange,
            200,
            "{\"email\":\"alice@example.com\",\"account\":\"1\",\"name\":\"Alice\"}",
            identities
        )
        assertTrue(verdict.vulnerable)
        assertEquals(Confidence.CERTAIN, verdict.confidence)
        assertTrue(verdict.markerSeen)
        assertTrue(verdict.similarity > 0.9)
    }

    @Test
    fun `identical response without an identity marker is firm`() {
        val exchange = TestData.exchange(
            request = originalRequest,
            response = "HTTP/1.1 200 OK\r\n\r\n{\"plan\":\"pro\",\"features\":[\"a\",\"b\",\"c\"]}"
        )
        val verdict = IdentitySwap.evaluate(
            exchange,
            200,
            "{\"plan\":\"pro\",\"features\":[\"a\",\"b\",\"c\"]}",
            identities
        )
        assertTrue(verdict.vulnerable)
        assertEquals(Confidence.FIRM, verdict.confidence)
        assertFalse(verdict.markerSeen)
    }

    @Test
    fun `rejects forbidden responses`() {
        val exchange = TestData.exchange(request = originalRequest)
        val verdict = IdentitySwap.evaluate(exchange, 403, "{\"error\":\"forbidden\"}", identities)
        assertFalse(verdict.vulnerable)
        assertTrue(verdict.reason.contains("403"))
    }

    @Test
    fun `rejects a much smaller error page`() {
        val exchange = TestData.exchange(
            request = originalRequest,
            response = "HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(5000)
        )
        val verdict = IdentitySwap.evaluate(exchange, 200, "no access", identities)
        assertFalse(verdict.vulnerable)
    }

    @Test
    fun `rejects a substantially different response`() {
        val exchange = TestData.exchange(
            request = originalRequest,
            response = "HTTP/1.1 200 OK\r\n\r\n" + "Account dashboard Alice orders invoices ".repeat(30)
        )
        val verdict = IdentitySwap.evaluate(
            exchange,
            200,
            "Completely different public marketing content with no account data ".repeat(30),
            identities
        )
        assertFalse(verdict.vulnerable)
    }

    @Test
    fun `similarity ignores key ordering noise`() {
        val one = """{"id":1,"name":"Alice","roles":["user"],"email":"alice@example.com"}"""
        val two = """{"email":"alice@example.com","roles":["user"],"name":"Alice","id":1}"""
        assertTrue(IdentitySwap.similarity(one, two) > 0.95)
    }
}
