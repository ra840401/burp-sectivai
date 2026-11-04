package io.sectiv.burp

import burp.api.montoya.MontoyaApi
import io.sectiv.burp.core.Confidence
import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.FindingStatus
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Severity
import io.sectiv.burp.core.StateRepository
import io.sectiv.burp.scan.ScanEngine
import io.sectiv.burp.ui.SectivPanel
import java.awt.image.BufferedImage
import java.lang.reflect.Method
import java.nio.file.Files
import javax.imageio.ImageIO
import javax.swing.JFrame
import javax.swing.SwingUtilities
import kotlin.test.Test

/**
 * Renders the dashboard with demo data so the repository can show a real
 * screenshot in the README.
 */
class DemoShots {
    @Test
    fun dashboardDemo() {
        val dir = Files.createTempDirectory("sectiv-demo")
        val store = SectivStore(StateRepository(dir.resolve("state.json")))
        val api = mockApi()
        val engine = ScanEngine(api, store)
        store.addFindings(demoFindings())

        var panel: SectivPanel? = null
        SwingUtilities.invokeAndWait { panel = SectivPanel(api, store, engine) }
        val frame = JFrame("Sectiv demo")
        frame.defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        frame.contentPane.add(panel!!)
        frame.setSize(1480, 960)
        frame.isVisible = true
        Thread.sleep(1400)
        SwingUtilities.invokeAndWait { frame.validate() }

        val out = java.io.File("design").apply { mkdirs() }
        SwingUtilities.invokeAndWait {
            val img = BufferedImage(panel!!.width.coerceAtLeast(1400), panel!!.height.coerceAtLeast(900), BufferedImage.TYPE_INT_RGB)
            val g = img.createGraphics()
            panel!!.paint(g)
            g.dispose()
            ImageIO.write(img, "png", java.io.File(out, "dashboard-demo.png"))
        }
        frame.dispose()
        engine.shutdown()
        store.close()
    }

    private fun demoFindings(): List<Finding> {
        val criticals = listOf(
            "Unauthenticated SQL injection in login endpoint" to "https://app.acme.test/api/auth/login",
            "Remote code execution via template injection" to "https://app.acme.test/api/render/preview",
            "Mass account takeover through password reset token leak" to "https://app.acme.test/api/auth/reset",
            "SSRF to cloud metadata from webhook import" to "https://app.acme.test/api/integrations/import",
            "Cross-tenant access to billing invoices (IDOR)" to "https://app.acme.test/api/v2/invoices/8841",
            "JWT algorithm confusion allows admin impersonation" to "https://app.acme.test/api/admin/users",
            "Stored XSS in support ticket attachments" to "https://app.acme.test/api/tickets/4821/attachments",
            "Command injection in report export filename" to "https://app.acme.test/api/reports/export",
            "Arbitrary file upload leads to webshell" to "https://app.acme.test/api/uploads/avatar",
            "Authentication bypass via signed cookie forgery" to "https://app.acme.test/api/session"
        )
        val highs = listOf(
            "Broken function-level authorization on admin export" to "https://app.acme.test/api/admin/export",
            "Reflected XSS in search results heading" to "https://app.acme.test/search?q=hello",
            "IDOR allows reading other users' order history" to "https://app.acme.test/api/orders/1024",
            "Business logic: negative quantity reduces order total" to "https://app.acme.test/api/cart/checkout"
        )
        val others = listOf(
            Triple("Sensitive data exposure in verbose API errors", Severity.MEDIUM, "https://app.acme.test/api/users/me"),
            Triple("Weak session cookie attributes", Severity.LOW, "https://app.acme.test/"),
            Triple("Server version disclosed in response headers", Severity.INFO, "https://app.acme.test/")
        )

        val findings = mutableListOf<Finding>()
        criticals.forEachIndexed { index, (title, url) ->
            findings += Finding(
                title = title,
                severity = Severity.CRITICAL,
                confidence = if (index % 3 == 0) Confidence.CERTAIN else Confidence.FIRM,
                url = url,
                method = if (url.contains("login") || url.contains("import") || url.contains("export") || url.contains("uploads")) "POST" else "GET",
                host = "app.acme.test",
                description = "The endpoint trusts client-supplied input without server-side validation. An attacker can exploit this to compromise the tenant boundary and read or modify data belonging to other customers.",
                stepsToReproduce = "1. Open Burp and capture a request to this endpoint.\n2. Replace the highlighted parameter with the payload shown in the PoC.\n3. Observe the server returns protected data or executes the supplied command.",
                impact = "Full compromise of the affected tenant: data loss, account takeover and lateral movement across the application.",
                poc = "curl -s '$url' -H 'Cookie: session=<USER_B_SESSION>'",
                pocType = "curl",
                evidence = "HTTP 200 · response contains cross-tenant data (alice@example.com)",
                remediation = "Validate and encode all input server-side, enforce object ownership and apply least privilege on every endpoint.",
                cwe = "CWE-639",
                cvss = 9.8,
                skillName = if (index % 2 == 0) "IDOR & BOLA" else "SQL Injection",
                fingerprint = "crit-$index"
            )
        }
        highs.forEachIndexed { index, (title, url) ->
            findings += Finding(
                title = title,
                severity = Severity.HIGH,
                confidence = Confidence.FIRM,
                url = url,
                method = "GET",
                host = "app.acme.test",
                description = "A lower-privileged user can reach functionality or data that should require higher privileges. The captured response confirms the action succeeded.",
                stepsToReproduce = "1. Log in as the standard user.\n2. Replay the captured request shown above.\n3. Confirm the privileged action completes with a 200 response.",
                impact = "Privilege escalation and unauthorized access to administrative or cross-user data.",
                poc = "curl -s '$url' -H 'Cookie: session=<USER_B_SESSION>'",
                pocType = "curl",
                evidence = "HTTP 200 · privileged action completed as standard user",
                remediation = "Enforce role checks server-side on every privileged handler.",
                cwe = "CWE-862",
                cvss = 8.1,
                skillName = "Function-Level Authorization",
                fingerprint = "high-$index"
            )
        }
        others.forEachIndexed { index, (title, severity, url) ->
            findings += Finding(
                title = title,
                severity = severity,
                confidence = if (index == 0) Confidence.FIRM else Confidence.TENTATIVE,
                url = url,
                method = "GET",
                host = "app.acme.test",
                description = "Observational finding with limited direct impact, but useful hardening signal for the engagement report.",
                stepsToReproduce = "1. Load the endpoint in Burp.\n2. Inspect the response body and headers.",
                impact = "Low direct impact; reduces the effort required for follow-on attacks.",
                poc = "curl -s '$url'",
                pocType = "curl",
                evidence = "Response contains the indicated disclosure.",
                remediation = "Apply the hardening guidance in the description.",
                cwe = if (severity == Severity.MEDIUM) "CWE-200" else "CWE-693",
                cvss = when (severity) {
                    Severity.MEDIUM -> 5.3
                    Severity.LOW -> 3.1
                    else -> 0.0
                },
                skillName = "Sensitive Data Exposure",
                fingerprint = "other-$index",
                status = if (index == 1) FindingStatus.TRIAGED else FindingStatus.OPEN
            )
        }
        return findings
    }

    private fun mockApi(): MontoyaApi {
        val scope = mock<burp.api.montoya.scope.Scope> { m, _ -> if (m.name == "isInScope") true else null }
        val proxy = mock<burp.api.montoya.proxy.Proxy> { m, _ -> if (m.name == "history") emptyList<Any>() else null }
        val siteMap = mock<burp.api.montoya.sitemap.SiteMap> { m, _ -> if (m.name == "requestResponses") emptyList<Any>() else null }
        return mock<MontoyaApi> { m, _ -> when (m.name) {
            "scope" -> scope; "proxy" -> proxy; "siteMap" -> siteMap; else -> null
        } }
    }

    private inline fun <reified T : Any> mock(noinline answer: (Method, Array<Any?>?) -> Any?): T {
        val handler = java.lang.reflect.InvocationHandler { proxy, method, args ->
            when (method.name) {
                "toString" -> "Mock"
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                else -> answer(method, args) ?: when {
                    method.returnType == java.lang.Boolean.TYPE -> false
                    method.returnType == java.lang.Integer.TYPE -> 0
                    List::class.java.isAssignableFrom(method.returnType) -> emptyList<Any>()
                    else -> null
                }
            }
        }
        return java.lang.reflect.Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java), handler) as T
    }
}
