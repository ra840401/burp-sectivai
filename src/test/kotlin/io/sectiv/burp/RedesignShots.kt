package io.sectiv.burp

import burp.api.montoya.MontoyaApi
import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Severity
import io.sectiv.burp.core.StateRepository
import io.sectiv.burp.scan.ScanEngine
import io.sectiv.burp.ui.SectivPanel
import java.awt.Font
import java.awt.image.BufferedImage
import java.lang.reflect.Method
import java.nio.file.Files
import javax.imageio.ImageIO
import javax.swing.JFrame
import javax.swing.SwingUtilities
import kotlin.test.Test

class RedesignShots {
    @Test
    fun shots() {
        val dir = Files.createTempDirectory("sectiv-redesign")
        val store = SectivStore(StateRepository(dir.resolve("state.json")))
        val api = mockApi()
        val engine = ScanEngine(api, store)
        store.addFindings(listOf(
            Finding(title = "Cross-tenant access to billing invoices", severity = Severity.CRITICAL,
                confidence = io.sectiv.burp.core.Confidence.CERTAIN,
                url = "https://app.acme.test/api/v2/invoices/8841", method = "GET", host = "app.acme.test",
                description = "Replaying the captured request with User B's session returned User A's invoice with a 200 response. The server appears to trust the client-supplied invoice identifier and does not scope the query to the authenticated tenant.",
                stepsToReproduce = "1. Log in as User B and open /api/v2/invoices/8841.\n2. Replace the session cookie with User A's cookie.\n3. Observe that User A's invoice data is returned with a 200 response.",
                impact = "Any authenticated user can read every customer invoice by enumerating the invoice identifier, exposing billing and PII at scale.",
                poc = "curl -s 'https://app.acme.test/api/v2/invoices/8841' -H 'Cookie: session=<USER_B_SESSION>'",
                pocType = "curl",
                evidence = "User B received HTTP 200 with a 96% response similarity.\nResponse contained alice@example.com and invoice 8841.",
                remediation = "Derive the tenant and owner from the authenticated session, then apply an ownership predicate to every invoice lookup. Return 404 for objects the caller does not own.",
                cwe = "CWE-639", cve = "", cvss = 9.1, skillName = "IDOR & BOLA", source = "identity-swap", fingerprint = "s1",
                requestRaw = "GET /api/v2/invoices/8841 HTTP/1.1\r\nHost: app.acme.test\r\n\r\n",
                responseRaw = "HTTP/1.1 200 OK\r\n\r\n{\"email\":\"alice@example.com\"}"),
            Finding(title = "Admin export endpoint reachable with a standard token", severity = Severity.HIGH,
                confidence = io.sectiv.burp.core.Confidence.FIRM,
                url = "https://app.acme.test/api/admin/export", method = "POST", host = "app.acme.test",
                description = "The export action returned a 202 for a regular user.",
                evidence = "POST /api/admin/export -> 202", remediation = "Enforce role checks.",
                skillName = "Function-Level Authorization", fingerprint = "s2"),
            Finding(title = "Order total accepted from the client", severity = Severity.MEDIUM,
                confidence = io.sectiv.burp.core.Confidence.FIRM,
                url = "https://app.acme.test/api/cart/checkout", method = "POST", host = "app.acme.test",
                description = "The checkout request includes a total field the server accepts.",
                evidence = "\"total\": 0.01", remediation = "Recalculate server-side.",
                skillName = "Business Logic", fingerprint = "s3"),
            Finding(title = "Reflected search term in HTML response", severity = Severity.LOW,
                confidence = io.sectiv.burp.core.Confidence.TENTATIVE,
                url = "https://app.acme.test/search?q=hello", method = "GET", host = "app.acme.test",
                description = "The q parameter is reflected in the results heading.",
                evidence = "<h1>Results for hello</h1>", remediation = "Encode output.",
                skillName = "Cross-Site Scripting", fingerprint = "s4"),
            Finding(title = "Server version disclosed in response header", severity = Severity.INFO,
                confidence = io.sectiv.burp.core.Confidence.CERTAIN,
                url = "https://app.acme.test/", method = "GET", host = "app.acme.test",
                description = "The Server header exposes a framework version.",
                evidence = "Server: nginx/1.25.3", remediation = "Suppress banners.",
                skillName = "Sensitive Data Exposure", fingerprint = "s5")
        ))

        var panel: SectivPanel? = null
        SwingUtilities.invokeAndWait { panel = SectivPanel(api, store, engine) }
        val frame = JFrame("Sectiv redesign")
        frame.defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        frame.contentPane.add(panel!!)
        frame.setSize(1480, 960)
        frame.isVisible = true
        Thread.sleep(1400)
        SwingUtilities.invokeAndWait { frame.validate() }

        val nav = panel!!.javaClass.getDeclaredField("nav").apply { isAccessible = true }.get(panel)
        val setIndex = nav.javaClass.getMethod("setSelectedIndex", Int::class.javaPrimitiveType)
        val out = java.io.File("build/ui-redesign").apply { mkdirs() }
        listOf("dashboard", "scan", "skills", "settings").forEachIndexed { index, name ->
            SwingUtilities.invokeAndWait {
                setIndex.invoke(nav, index)
                frame.validate()
                panel!!.repaint()
            }
            Thread.sleep(600)
            SwingUtilities.invokeAndWait {
                val img = BufferedImage(panel!!.width.coerceAtLeast(1400), panel!!.height.coerceAtLeast(900), BufferedImage.TYPE_INT_RGB)
                val g = img.createGraphics()
                panel!!.paint(g)
                g.dispose()
                ImageIO.write(img, "png", java.io.File(out, "$name.png"))
            }
        }
        frame.dispose()
        engine.shutdown()
        store.close()
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
