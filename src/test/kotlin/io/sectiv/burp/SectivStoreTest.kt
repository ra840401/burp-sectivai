package io.sectiv.burp

import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.ProviderConfig
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Severity
import io.sectiv.burp.core.Skill
import io.sectiv.burp.core.StateRepository
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SectivStoreTest {

    private val dir = Files.createTempDirectory("sectiv-test")
    private val path = dir.resolve("state.json")
    private var store: SectivStore? = null

    @AfterTest
    fun cleanup() {
        runCatching { store?.close() }
        dir.toFile().deleteRecursively()
    }

    @Test
    fun `adds findings and deduplicates fingerprints`() {
        store = SectivStore(StateRepository(path))
        val first = Finding(title = "IDOR", severity = Severity.HIGH, fingerprint = "abc", url = "https://x/1")
        val second = Finding(title = "XSS", severity = Severity.MEDIUM, fingerprint = "def", url = "https://x/2")
        assertEquals(2, store!!.addFindings(listOf(first, second)))
        assertEquals(0, store!!.addFindings(listOf(first.copy(id = "other"))))
        assertEquals(2, store!!.state().findings.size)
    }

    @Test
    fun `persists settings skills and findings across restarts`() {
        store = SectivStore(StateRepository(path))
        val settings = store!!.state().settings
        val deepseek = settings.activeProvider().copy(apiKey = "sk-test-secret")
        store!!.setSettings(
            settings.copy(
                activeProviderId = deepseek.id,
                providers = settings.providers.map { if (it.id == deepseek.id) deepseek else it },
                maxSwapRequests = 7
            )
        )
        store!!.upsertSkill(Skill(id = "custom", name = "My custom skill", instructions = "Look for X."))
        store!!.addFindings(listOf(Finding(title = "Persisted", severity = Severity.CRITICAL, fingerprint = "p1")))
        store!!.setAuthContext("User A cookie: session=aaa")
        store!!.flush()
        store!!.close()
        store = null

        assertTrue(Files.exists(path))
        val reloaded = SectivStore(StateRepository(path))
        store = reloaded
        val state = reloaded.state()
        assertEquals("sk-test-secret", state.settings.activeProvider().apiKey)
        assertEquals(7, state.settings.maxSwapRequests)
        assertTrue(state.skills.any { it.id == "custom" })
        assertTrue(state.findings.any { it.title == "Persisted" })
        assertEquals("User A cookie: session=aaa", state.authContext)
        val perms = runCatching { Files.getPosixFilePermissions(path) }.getOrNull()
        if (perms != null) {
            assertTrue(perms.none { it.name.startsWith("GROUP") || it.name.startsWith("OTHERS") })
        }
    }

    @Test
    fun `restores missing provider presets`() {
        store = SectivStore(StateRepository(path))
        val settings = store!!.state().settings
        val onlyDeepSeek = settings.copy(
            providers = listOf(settings.providers.first { it.id == "deepseek" }),
            activeProviderId = "deepseek"
        )
        store!!.setSettings(onlyDeepSeek)
        val providers = store!!.state().settings.providers
        assertTrue(providers.any { it.id == "anthropic" })
        assertTrue(providers.any { it.id == "openrouter" })
    }

    @Test
    fun `updating a finding status persists`() {
        store = SectivStore(StateRepository(path))
        val finding = Finding(title = "Test", severity = Severity.LOW, fingerprint = "f1")
        store!!.addFindings(listOf(finding))
        store!!.updateFinding(finding.id) { it.copy(status = io.sectiv.burp.core.FindingStatus.FALSE_POSITIVE) }
        assertEquals(
            io.sectiv.burp.core.FindingStatus.FALSE_POSITIVE,
            store!!.state().findings.first().status
        )
    }

    @Test
    fun `corrupt state file falls back to defaults`() {
        Files.writeString(path, "{not json")
        store = SectivStore(StateRepository(path))
        assertTrue(store!!.state().skills.isNotEmpty())
        assertTrue(
            Files.list(dir).use { stream ->
                stream.anyMatch { it.fileName.toString().startsWith("state.json.corrupt-") }
            }
        )
    }

    @Test
    fun `provider config round trips`() {
        val provider = ProviderConfig(
            id = "my-custom",
            name = "Custom",
            baseUrl = "https://example.test/v1/chat/completions",
            model = "model-x",
            apiKey = "k",
            extraHeaders = mapOf("X-Test" to "1"),
            extraBodyJson = """{"top_p":0.9}"""
        )
        store = SectivStore(StateRepository(path))
        val settings = store!!.state().settings
        store!!.setSettings(settings.copy(providers = settings.providers + provider, activeProviderId = provider.id))
        store!!.flush()
        store!!.close()
        store = null

        val reloaded = SectivStore(StateRepository(path))
        store = reloaded
        val loaded = reloaded.state().settings.activeProvider()
        assertEquals("model-x", loaded.model)
        assertEquals("1", loaded.extraHeaders["X-Test"])
        assertTrue(loaded.extraBodyJson.contains("top_p"))
    }
}
