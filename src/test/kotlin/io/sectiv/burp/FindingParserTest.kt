package io.sectiv.burp

import io.sectiv.burp.ai.FindingParser
import io.sectiv.burp.core.Confidence
import io.sectiv.burp.core.Severity
import io.sectiv.burp.core.Skill
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FindingParserTest {

    private val skill = Skill(
        id = "skill-idor",
        name = "IDOR & BOLA",
        instructions = "Review for object-level authorization issues."
    )

    @Test
    fun `parses fenced json with common aliases`() {
        val raw = """
            Here is the result:
            ```json
            {
              "findings": [
                {
                  "name": "IDOR on user profile",
                  "risk": "high",
                  "likelihood": "likely",
                  "endpoint": "https://app.example.com/api/users/123?token=abc",
                  "http_method": "get",
                  "detail": "The endpoint returns another user's profile.",
                  "proof": "response contained bob@example.com",
                  "fix": "Check object ownership.",
                  "cwe_id": "CWE-639",
                  "cvss_score": "8.1"
                }
              ]
            }
            ```
        """.trimIndent()

        val result = FindingParser.parse(raw, skill, maxFindings = 5)
        assertNull(result.error)
        assertEquals(1, result.findings.size)
        val finding = result.findings.first()
        assertEquals("IDOR on user profile", finding.title)
        assertEquals(Severity.HIGH, finding.severity)
        assertEquals(Confidence.FIRM, finding.confidence)
        assertEquals("GET", finding.method)
        assertEquals("CWE-639", finding.cwe)
        assertEquals(8.1, finding.cvss)
        assertEquals("skill-idor", finding.skillId)
        assertTrue(finding.fingerprint.isNotBlank())
    }

    @Test
    fun `accepts a single finding object and infers info severity`() {
        val raw = """{"title":"Missing security header","severity":"weird","description":"No CSP","url":"https://x.test/"}"""
        val result = FindingParser.parse(raw, skill)
        assertNull(result.error)
        assertEquals(1, result.findings.size)
        assertEquals(Severity.INFO, result.findings.first().severity)
    }

    @Test
    fun `repairs trailing commas`() {
        val raw = """{"findings":[{"title":"Test","severity":"low","url":"https://x.test/",},],}"""
        val result = FindingParser.parse(raw, skill)
        assertNull(result.error)
        assertEquals(1, result.findings.size)
    }

    @Test
    fun `deduplicates identical findings`() {
        val raw = """
            {"findings":[
              {"title":"Same bug","severity":"high","method":"GET","url":"https://x.test/a/1"},
              {"title":"Same bug","severity":"high","method":"GET","url":"https://x.test/a/2"}
            ]}
        """.trimIndent()
        val result = FindingParser.parse(raw, skill)
        assertEquals(1, result.findings.size)
    }

    @Test
    fun `returns empty list for a clean review`() {
        val result = FindingParser.parse("""{"findings":[]}""", skill)
        assertNull(result.error)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `reports invalid json`() {
        val result = FindingParser.parse("this is not json", skill)
        assertNotNull(result.error)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `respects max findings`() {
        val raw = """{"findings":[
            {"title":"A","severity":"high","url":"https://x.test/1"},
            {"title":"B","severity":"high","url":"https://x.test/2"},
            {"title":"C","severity":"high","url":"https://x.test/3"}
        ]}"""
        val result = FindingParser.parse(raw, skill, maxFindings = 2)
        assertEquals(2, result.findings.size)
    }

    @Test
    fun `normalizes ids and query values for fingerprints`() {
        val one = FindingParser.fingerprint("IDOR", "GET", "https://x.test/api/users/123?token=abc")
        val two = FindingParser.fingerprint("IDOR", "GET", "https://x.test/api/users/456?token=zzz")
        assertEquals(one, two)
        assertTrue(FindingParser.normalizeUrl("https://x.test/api/users/123?token=abc").contains("{id}"))
    }

    @Test
    fun `extracts only the json object from surrounding prose`() {
        val extracted = FindingParser.extractJson("prefix {\"findings\":[]} suffix")
        assertEquals("{\"findings\":[]}", extracted)
    }
}
