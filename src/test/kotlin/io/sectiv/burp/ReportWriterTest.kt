package io.sectiv.burp

import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.FindingStatus
import io.sectiv.burp.core.Severity
import io.sectiv.burp.report.ReportMeta
import io.sectiv.burp.report.ReportWriter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReportWriterTest {

    private val findings = listOf(
        Finding(
            title = "Reflected <script> XSS",
            severity = Severity.MEDIUM,
            url = "https://app.example.com/search?q=%3Cscript%3E",
            method = "GET",
            description = "The q parameter is reflected unencoded.",
            evidence = "<script>alert(1)</script>",
            remediation = "Encode output.",
            skillName = "XSS"
        ),
        Finding(
            title = "Cross-account access",
            severity = Severity.CRITICAL,
            url = "https://app.example.com/api/account/1",
            method = "GET",
            description = "User B can read User A's account.",
            evidence = "HTTP 200 with alice@example.com",
            remediation = "Enforce object ownership.",
            cwe = "CWE-639",
            cvss = 9.1,
            source = "identity-swap",
            status = FindingStatus.OPEN,
            skillName = "Identity swap verification"
        )
    )

    private val meta = ReportMeta(
        title = "Acme review",
        target = "app.example.com",
        provider = "DeepSeek · deepseek-chat",
        generatedAt = 1_700_000_000_000
    )

    @Test
    fun `json includes summary and all findings`() {
        val json = ReportWriter.toJson(findings, meta)
        assertTrue(json.contains("\"title\" : \"Acme review\""))
        assertTrue(json.contains("\"critical\" : 1"))
        assertTrue(json.contains("Cross-account access"))
        assertTrue(json.contains("CWE-639"))
    }

    @Test
    fun `markdown is ordered by severity and escapes nothing needed`() {
        val markdown = ReportWriter.toMarkdown(findings, meta)
        val criticalIndex = markdown.indexOf("Cross-account access")
        val mediumIndex = markdown.indexOf("Reflected <script> XSS")
        assertTrue(criticalIndex in 0 until mediumIndex)
        assertTrue(markdown.contains("| **Total** | **2** |"))
        assertTrue(markdown.contains("Active identity-swap check"))
    }

    @Test
    fun `html escapes evidence and titles`() {
        val html = ReportWriter.toHtml(findings, meta)
        assertTrue(html.contains("Reflected &lt;script&gt; XSS"))
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"))
        assertTrue(!html.contains("<script>alert(1)</script>"))
        assertTrue(html.contains("Acme review"))
    }

    @Test
    fun `empty report is valid`() {
        assertTrue(ReportWriter.toHtml(emptyList(), meta).contains("No findings"))
        assertEquals(0, ReportWriter.openFindings(emptyList()))
    }
}
