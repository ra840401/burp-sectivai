package io.sectiv.burp

import burp.api.montoya.MontoyaApi
import io.sectiv.burp.ai.LlmGateway
import io.sectiv.burp.ai.LlmReply
import io.sectiv.burp.ai.LlmUsage
import io.sectiv.burp.core.ProviderConfig
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Settings
import io.sectiv.burp.core.Skill
import io.sectiv.burp.core.StateRepository
import io.sectiv.burp.scan.LogLevel
import io.sectiv.burp.scan.ScanEngine
import io.sectiv.burp.scan.ScanListener
import io.sectiv.burp.scan.ScanRequest
import io.sectiv.burp.scan.ScanStage
import io.sectiv.burp.scan.ScanSummary
import java.nio.file.Files
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ScanEngineTest {

    private val dir = Files.createTempDirectory("sectiv-scan-test")
    private var store: SectivStore? = null
    private var engine: ScanEngine? = null

    @AfterTest
    fun cleanup() {
        runCatching { engine?.shutdown() }
        runCatching { store?.close() }
        dir.toFile().deleteRecursively()
    }

    @Test
    fun `runs an AI review and enriches findings from captured traffic`() {
        val localStore = SectivStore(StateRepository(dir.resolve("state.json")))
        store = localStore
        val gateway = FakeLlm(
            """
            {"findings":[{
              "title":"IDOR on account endpoint",
              "severity":"high",
              "confidence":"firm",
              "url":"https://app.example.com/api/account/1",
              "method":"GET",
              "description":"The account ID is trusted.",
              "evidence":"HTTP 200 with alice@example.com",
              "remediation":"Enforce ownership.",
              "cwe":"CWE-639"
            }]}
            """.trimIndent()
        )
        val localEngine = ScanEngine(mockApi(), localStore, gateway)
        engine = localEngine

        val exchange = TestData.exchange(
            id = "account-1",
            url = "https://app.example.com/api/account/1",
            path = "/api/account/1",
            request = "GET /api/account/1 HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=aaa\r\n\r\n",
            response = "HTTP/1.1 200 OK\r\n\r\n{\"email\":\"alice@example.com\"}"
        )
        val outcome = runScan(localEngine, localStore, listOf(exchange), gateway)
        assertTrue(outcome.summary.addedFindings == 1)
        assertEquals(1, localStore.state().findings.size)
        val finding = localStore.state().findings.first()
        assertEquals("GET", finding.method)
        assertEquals("app.example.com", finding.host)
        assertTrue(finding.requestRaw.contains("GET /api/account/1"))
        assertTrue(finding.responseRaw.contains("alice@example.com"))
        assertEquals("IDOR on account endpoint", finding.title)
        assertTrue(outcome.logs.any { it.contains("Provider:") })
        assertTrue(outcome.progress.any { it.stage == ScanStage.AI_REVIEW })
        assertNotNull(outcome.summary)

        val prompt = gateway.calls.firstOrNull()?.second.orEmpty()
        assertTrue(prompt.contains("alice@example.com"), "email context should remain visible")
        assertTrue(prompt.contains("[USER_A_COOKIE]"), "cookie should be replaced by an identity marker")
        assertTrue(prompt.contains("[USER_B_COOKIE]"), "cookie should be replaced by an identity marker")
        assertTrue(!prompt.contains("session=aaa"), "raw User A cookie must not be sent to the model")
        assertTrue(!prompt.contains("session=bbb"), "raw User B cookie must not be sent to the model")
    }

    @Test
    fun `duplicate findings are counted but not stored twice`() {
        val localStore = SectivStore(StateRepository(dir.resolve("state.json")))
        store = localStore
        val gateway = FakeLlm("""{"findings":[{"title":"Same","severity":"medium","url":"https://app.example.com/x","method":"GET"}]}""")
        val localEngine = ScanEngine(mockApi(), localStore, gateway)
        engine = localEngine
        val exchange = TestData.exchange(url = "https://app.example.com/x", path = "/x")

        val first = runScan(localEngine, localStore, listOf(exchange), gateway)
        val second = runScan(localEngine, localStore, listOf(exchange), gateway)
        assertEquals(1, first.summary.addedFindings)
        assertEquals(0, second.summary.addedFindings)
        assertEquals(1, second.summary.duplicateFindings)
        assertEquals(1, localStore.state().findings.size)
    }

    @Test
    fun `retries once when the model returns invalid JSON`() {
        val localStore = SectivStore(StateRepository(dir.resolve("state.json")))
        store = localStore
        val gateway = FakeLlm(
            "not json at all",
            """{"findings":[{"title":"Recovered","severity":"high","url":"https://app.example.com/x","method":"GET"}]}"""
        )
        val localEngine = ScanEngine(mockApi(), localStore, gateway)
        engine = localEngine
        val exchange = TestData.exchange(url = "https://app.example.com/x", path = "/x")
        val outcome = runScan(localEngine, localStore, listOf(exchange), gateway)
        assertEquals(2, outcome.summary.aiCalls)
        assertEquals(1, outcome.summary.addedFindings)
        assertTrue(outcome.logs.any { it.contains("could not be parsed", ignoreCase = true) })
    }

    @Test
    fun `records failed model calls and still finishes`() {
        val localStore = SectivStore(StateRepository(dir.resolve("state.json")))
        store = localStore
        val gateway = object : LlmGateway {
            override fun complete(
                provider: ProviderConfig,
                system: String,
                user: String,
                cancel: () -> Boolean,
                maxAttempts: Int,
                allowEmpty: Boolean
            ) = throw io.sectiv.burp.ai.LlmException("upstream exploded")

            override fun ping(provider: ProviderConfig) = "OK"
        }
        val localEngine = ScanEngine(mockApi(), localStore, gateway)
        engine = localEngine
        val exchange = TestData.exchange(url = "https://app.example.com/x", path = "/x")
        val outcome = runScan(localEngine, localStore, listOf(exchange), gateway)
        assertEquals(1, outcome.summary.failedAiCalls)
        assertEquals(0, outcome.summary.addedFindings)
        assertTrue(outcome.logs.any { it.contains("upstream exploded") })
    }

    private fun runScan(
        engine: ScanEngine,
        store: SectivStore,
        exchanges: List<io.sectiv.burp.core.CapturedExchange>,
        gateway: LlmGateway
    ): Outcome {
        val latch = CountDownLatch(1)
        val logs = CopyOnWriteArrayList<String>()
        val progress = CopyOnWriteArrayList<Pair<ScanStage, String>>()
        val summary = AtomicReference<ScanSummary>()
        val failure = AtomicReference<String>()
        val listener = object : ScanListener {
            override fun onLog(message: String, level: LogLevel) {
                logs += message
            }

            override fun onProgress(stage: ScanStage, message: String, done: Int, total: Int) {
                progress += stage to message
            }

            override fun onFindingsAdded(count: Int) = Unit

            override fun onFinished(result: ScanSummary) {
                summary.set(result)
                latch.countDown()
            }

            override fun onFailed(message: String, error: Throwable?) {
                failure.set(message)
                latch.countDown()
            }
        }
        val request = ScanRequest(
            exchanges = exchanges,
            skills = listOf(
                Skill(
                    id = "skill-idor",
                    name = "IDOR & BOLA",
                    instructions = "Look for object-level authorization issues."
                )
            ),
            authContext = "User A cookie: session=aaa\nUser B cookie: session=bbb",
            provider = Settings().activeProvider(),
            settings = Settings(chunkChars = 9_000, maxFindingsPerChunk = 5),
            identitySwap = false
        )
        val handle = engine.scan(request, listener)
        assertTrue(latch.await(10, TimeUnit.SECONDS), "scan did not finish")
        assertEquals(null, failure.get(), "scan failed: ${failure.get()}")
        assertNotNull(summary.get())
        return Outcome(summary.get()!!, logs, progress.map { Progress(it.first, it.second) })
    }

    private fun mockApi(): MontoyaApi {
        val handler = java.lang.reflect.InvocationHandler { proxy, method, args ->
            when (method.name) {
                "toString" -> "MockMontoyaApi"
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                else -> null
            }
        }
        return java.lang.reflect.Proxy.newProxyInstance(
            MontoyaApi::class.java.classLoader,
            arrayOf(MontoyaApi::class.java),
            handler
        ) as MontoyaApi
    }

    private data class Outcome(
        val summary: ScanSummary,
        val logs: List<String>,
        val progress: List<Progress>
    )

    private data class Progress(val stage: ScanStage, val message: String)

    private class FakeLlm(vararg responses: String) : LlmGateway {
        private val responses = responses.toList()
        private var index = 0
        val calls = CopyOnWriteArrayList<Pair<String, String>>()

        override fun complete(
            provider: ProviderConfig,
            system: String,
            user: String,
            cancel: () -> Boolean,
            maxAttempts: Int,
            allowEmpty: Boolean
        ): LlmReply {
            calls += system to user
            val response = responses[minOf(index, responses.lastIndex)]
            index++
            return LlmReply(response, LlmUsage(120, 60))
        }

        override fun ping(provider: ProviderConfig): String = "OK"
    }
}
