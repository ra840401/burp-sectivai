package io.sectiv.burp

import io.sectiv.burp.ai.PromptBuilder
import io.sectiv.burp.core.IdentityPair
import io.sectiv.burp.core.IdentityProfile
import io.sectiv.burp.core.Settings
import io.sectiv.burp.core.Skill
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PromptBuilderTest {

    private val skill = Skill(
        id = "skill-idor",
        name = "IDOR & BOLA",
        instructions = "Look for object identifiers that are not scoped to the authenticated user."
    )

    private val identities = IdentityPair(
        IdentityProfile("A", email = "alice@example.com", cookie = "session=aaa"),
        IdentityProfile("B", email = "bob@example.com", cookie = "session=bbb")
    )

    @Test
    fun `packs exchanges into chunks without losing any`() {
        val exchanges = (1..6).map { index ->
            TestData.exchange(
                id = "e$index",
                url = "https://app.example.com/api/users/$index",
                path = "/api/users/$index",
                request = "GET /api/users/$index HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=aaa\r\n\r\n",
                response = "HTTP/1.1 200 OK\r\n\r\n" + "response-$index ".repeat(400)
            )
        }
        val prompt = PromptBuilder.build(
            skill,
            exchanges,
            Settings(chunkChars = 9_000),
            identities,
            "User A cookie: session=aaa\nUser B cookie: session=bbb"
        )
        assertTrue(prompt.chunks.isNotEmpty())
        assertEquals(exchanges.map { it.id }.toSet(), prompt.chunks.flatMap { it.exchangeIds }.toSet())
        assertTrue(prompt.system.contains("IDOR & BOLA"))
        assertTrue(prompt.system.contains("JSON"))
        assertTrue(prompt.chunks.all { it.traffic.isNotBlank() })
    }

    @Test
    fun `user prompt includes identity context and chunk position`() {
        val exchange = TestData.exchange()
        val prompt = PromptBuilder.build(
            skill,
            listOf(exchange),
            Settings(),
            identities,
            "User A email: alice@example.com\nUser B email: bob@example.com"
        )
        val user = PromptBuilder.userPrompt(
            skill.name,
            "User A email: alice@example.com\nUser B email: bob@example.com",
            prompt.chunks.first(),
            0,
            prompt.chunks.size
        )
        assertTrue(user.contains("alice@example.com"))
        assertTrue(user.contains("TRAFFIC CHUNK 1 OF 1"))
        assertTrue(user.contains("https://app.example.com/api/users/1"))
    }

    @Test
    fun `large single exchange is clipped to the budget`() {
        val exchange = TestData.exchange(
            response = "HTTP/1.1 200 OK\r\n\r\n" + "z".repeat(100_000)
        )
        val prompt = PromptBuilder.build(
            skill,
            listOf(exchange),
            Settings(chunkChars = 9_000, maxResponseChars = 50_000),
            identities,
            ""
        )
        assertEquals(1, prompt.chunks.size)
        assertTrue(prompt.chunks.first().traffic.length <= 9_000 + 500)
        assertTrue(prompt.chunks.first().traffic.contains("truncated"))
    }

    @Test
    fun `system prompt asks for no findings when evidence is absent`() {
        val system = PromptBuilder.systemPrompt(skill, Settings(maxFindingsPerChunk = 3))
        assertTrue(system.contains("empty findings array"))
        assertTrue(system.contains("at most 3 findings"))
    }
}
