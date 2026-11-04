package io.sectiv.burp

import io.sectiv.burp.core.IdentityContextParser
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IdentityContextParserTest {

    @Test
    fun `parses the UI template`() {
        val pair = IdentityContextParser.parse(IdentityContextParser.TEMPLATE)
        val a = assertNotNull(pair.a)
        val b = assertNotNull(pair.b)
        assertEquals("alice@example.com", a.email)
        // Placeholder values must not be treated as real credentials.
        assertNull(a.cookie)
        assertNull(a.authorization)
        assertEquals("bob@example.com", b.email)
        assertNull(b.cookie)
        assertTrue(!pair.hasCompleteCredentials)
        assertTrue(!pair.swappable)
    }

    @Test
    fun `parses block layout with bare user headers`() {
        val text = """
            User A
              email: alice@example.com
              Cookie: session=aaa; theme=light
              Authorization: Bearer AAA

            User B
              email: bob@example.com
              Cookie: session=bbb; theme=dark
              Authorization: Bearer BBB
        """.trimIndent()

        val pair = IdentityContextParser.parse(text)
        assertEquals("session=aaa; theme=light", pair.a?.cookie)
        assertEquals("Bearer BBB", pair.b?.authorization)
        assertTrue(pair.swappable)
    }

    @Test
    fun `parses one-line notes`() {
        val text = "User A cookie is: session=aaa; theme=light\n" +
            "User B cookie is: session=bbb"
        val pair = IdentityContextParser.parse(text)
        assertEquals("session=aaa; theme=light", pair.a?.cookie)
        assertEquals("session=bbb", pair.b?.cookie)
        assertTrue(pair.swappable)
    }

    @Test
    fun `parses email-first sentence`() {
        val text = "User A is a user with email alice@example.com and User B is a user with email bob@example.com"
        val pair = IdentityContextParser.parse(text)
        assertEquals("alice@example.com", pair.a?.email)
        assertEquals("bob@example.com", pair.b?.email)
        assertTrue(pair.hasAnyIdentity)
    }

    @Test
    fun `normalizes a bare token into a bearer header`() {
        val text = """
            User A
              Authorization: abc.def.ghi
            User B
              Authorization: Bearer xyz
        """.trimIndent()
        val pair = IdentityContextParser.parse(text)
        assertEquals("Bearer abc.def.ghi", pair.a?.authorization)
        assertEquals("Bearer xyz", pair.b?.authorization)
    }

    @Test
    fun `empty text has no identities`() {
        val pair = IdentityContextParser.parse("")
        assertNull(pair.a)
        assertNull(pair.b)
        assertTrue(!pair.hasAnyIdentity)
        assertTrue(!pair.swappable)
    }

    @Test
    fun `partial context is not swappable`() {
        val pair = IdentityContextParser.parse("User A cookie is: session=aaa")
        assertEquals("session=aaa", pair.a?.cookie)
        assertNull(pair.b)
        assertTrue(!pair.swappable)
    }
}
