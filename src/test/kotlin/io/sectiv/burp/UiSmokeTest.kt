package io.sectiv.burp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.Extension
import burp.api.montoya.logging.Logging
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.scope.Scope
import burp.api.montoya.sitemap.SiteMap
import burp.api.montoya.ui.Theme
import burp.api.montoya.ui.UserInterface
import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Severity
import io.sectiv.burp.core.StateRepository
import io.sectiv.burp.scan.ScanEngine
import io.sectiv.burp.ui.SectivPanel
import java.awt.Font
import java.lang.reflect.Method
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import javax.swing.SwingUtilities
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UiSmokeTest {

    private val dir = Files.createTempDirectory("sectiv-ui-test")
    private var store: SectivStore? = null
    private var engine: ScanEngine? = null

    @AfterTest
    fun cleanup() {
        runCatching { engine?.shutdown() }
        runCatching { store?.close() }
        dir.toFile().deleteRecursively()
    }

    @Test
    fun `suite tab builds renders findings and handles empty history`() {
        val errors = CopyOnWriteArrayList<Throwable>()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, error -> errors += error }
        try {
            val api = mockApi()
            val localStore = SectivStore(StateRepository(dir.resolve("state.json")))
            store = localStore
            val localEngine = ScanEngine(api, localStore)
            engine = localEngine

            var panel: SectivPanel? = null
            SwingUtilities.invokeAndWait { panel = SectivPanel(api, localStore, localEngine) }
            assertTrue(panel != null)

            localStore.addFindings(
                listOf(
                    Finding(
                        title = "IDOR on account",
                        severity = Severity.HIGH,
                        url = "https://app.example.com/api/account/1",
                        method = "GET",
                        host = "app.example.com",
                        description = "Cross-account data.",
                        evidence = "alice@example.com",
                        remediation = "Check ownership.",
                        fingerprint = "ui-test-1"
                    )
                )
            )

            // Let the history-loading timer and store listeners run on the EDT.
            repeat(16) {
                SwingUtilities.invokeAndWait { }
                Thread.sleep(60)
            }

            assertEquals(1, localStore.state().findings.size)
            SwingUtilities.invokeAndWait { panel?.close() }
            panel = null

            assertTrue(errors.isEmpty(), "EDT errors: ${errors.joinToString(" | ") { it.stackTraceToString() }}")
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(previous)
        }
    }

    private fun mockApi(): MontoyaApi {
        val ui = mock<UserInterface> { method, _ ->
            when (method.name) {
                "currentTheme" -> Theme.DARK
                "currentDisplayFont" -> Font(Font.SANS_SERIF, Font.PLAIN, 12)
                "currentEditorFont" -> Font(Font.MONOSPACED, Font.PLAIN, 12)
                else -> null
            }
        }
        val scope = mock<Scope> { method, args ->
            if (method.name == "isInScope") true else null
        }
        val proxy = mock<Proxy> { method, _ ->
            if (method.name == "history") emptyList<Any>() else null
        }
        val siteMap = mock<SiteMap> { method, _ ->
            if (method.name == "requestResponses") emptyList<Any>() else null
        }
        val extension = mock<Extension> { _, _ -> null }
        val logging = mock<Logging> { _, _ -> null }

        return mock<MontoyaApi> { method, _ ->
            when (method.name) {
                "userInterface" -> ui
                "scope" -> scope
                "proxy" -> proxy
                "siteMap" -> siteMap
                "extension" -> extension
                "logging" -> logging
                else -> null
            }
        }
    }

    private inline fun <reified T : Any> mock(
        noinline answer: (Method, Array<Any?>?) -> Any?
    ): T {
        val handler = java.lang.reflect.InvocationHandler { proxy, method, args ->
            when (method.name) {
                "toString" -> "Mock${T::class.simpleName}"
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                else -> {
                    val result = answer(method, args)
                    result ?: defaultValue(method.returnType)
                }
            }
        }
        return java.lang.reflect.Proxy.newProxyInstance(
            T::class.java.classLoader,
            arrayOf(T::class.java),
            handler
        ) as T
    }

    private fun defaultValue(type: Class<*>): Any? = when {
        type == java.lang.Boolean.TYPE -> false
        type == java.lang.Integer.TYPE -> 0
        type == java.lang.Long.TYPE -> 0L
        type == java.lang.Short.TYPE -> 0.toShort()
        type == java.lang.Byte.TYPE -> 0.toByte()
        type == java.lang.Double.TYPE -> 0.0
        type == java.lang.Float.TYPE -> 0f
        type == java.lang.Character.TYPE -> ' '
        type == String::class.java -> ""
        List::class.java.isAssignableFrom(type) -> emptyList<Any>()
        java.util.Optional::class.java.isAssignableFrom(type) -> java.util.Optional.empty<Any>()
        else -> null
    }
}
