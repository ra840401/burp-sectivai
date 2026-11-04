package io.sectiv.burp.ai

import com.fasterxml.jackson.databind.JsonNode
import io.sectiv.burp.core.Confidence
import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.Json
import io.sectiv.burp.core.Nodes
import io.sectiv.burp.core.Severity
import io.sectiv.burp.core.Skill
import java.security.MessageDigest
import java.util.HexFormat

data class ParseResult(
    val findings: List<Finding>,
    val error: String? = null,
    val notes: List<String> = emptyList()
)

/**
 * Defensive parser for model output. Handles code fences, surrounding prose,
 * aliases used by different models and minor JSON mistakes.
 */
object FindingParser {

    fun parse(raw: String, skill: Skill, maxFindings: Int = 10): ParseResult {
        if (raw.isBlank()) return ParseResult(emptyList(), error = "The model returned an empty response.")
        val json = extractJson(raw)
            ?: return ParseResult(emptyList(), error = "No JSON object found in the model response.")

        var root: JsonNode? = try {
            Json.parseTree(json)
        } catch (_: Exception) {
            try {
                Json.parseTree(repairTrailingCommas(json))
            } catch (e: Exception) {
                null
            }
        }
        root ?: return ParseResult(emptyList(), error = "The model returned invalid JSON.")

        val array = when {
            root.isArray -> root
            root.isObject -> {
                val nested = Nodes.field(root, "findings", "results", "issues", "vulnerabilities")
                when {
                    nested != null && nested.isArray -> nested
                    Nodes.field(root, "title", "name", "issue") != null -> Json.mapper.createArrayNode().add(root)
                    else -> Json.mapper.createArrayNode()
                }
            }
            else -> Json.mapper.createArrayNode()
        }

        val notes = mutableListOf<String>()
        val findings = mutableListOf<Finding>()
        for (node in array) {
            if (findings.size >= maxFindings) {
                notes += "Response contained more than $maxFindings findings; extras were dropped."
                break
            }
            if (!node.isObject) continue
            val finding = parseFinding(node, skill, notes) ?: continue
            findings += finding
        }

        val deduped = findings.distinctBy { it.fingerprint }
        if (deduped.size != findings.size) {
            notes += "${findings.size - deduped.size} duplicate finding(s) in the model response were merged."
        }
        return ParseResult(deduped, notes = notes)
    }

    private fun parseFinding(node: JsonNode, skill: Skill, notes: MutableList<String>): Finding? {
        val title = Nodes.text(node, "title", "name", "issue", "vulnerability")
            ?: return null
        if (title.isBlank()) return null

        val severityRaw = Nodes.text(node, "severity", "risk", "rating")
        val severity = Severity.from(severityRaw)
        if (severityRaw != null && severity == null) {
            notes += "Unknown severity '$severityRaw' mapped to Info."
        }
        val resolvedSeverity = severity ?: Severity.INFO

        val method = Nodes.text(node, "method", "http_method")?.uppercase()?.take(12).orEmpty()
        val url = Nodes.text(node, "url", "endpoint", "uri", "location")
            ?.lineSequence()?.firstOrNull()?.trim().orEmpty()

        val description = buildDescription(node)
        val stepsToReproduce = Nodes.text(
            node,
            "stepsToReproduce", "steps_to_reproduce", "steps", "reproduction_steps", "repro_steps"
        )?.take(8000).orEmpty()
        val impact = Nodes.text(node, "impact", "business_impact", "consequence")
            ?.take(6000).orEmpty()
        val poc = Nodes.text(node, "poc", "proof_of_concept", "poc_code", "pocCode", "exploit_code")
            ?.take(12000).orEmpty()
        val pocType = normalizePocType(
            Nodes.text(node, "pocType", "poc_type", "poc_format"),
            poc
        )
        val evidence = Nodes.text(node, "evidence", "proof", "request_response", "observation")
            ?.take(8000).orEmpty()
        val remediation = Nodes.text(node, "remediation", "fix", "recommendation", "mitigation")
            ?.take(5000).orEmpty()
        val cwe = normalizeCwe(Nodes.text(node, "cwe", "cwe_id", "weakness"))
        val cve = normalizeCve(Nodes.text(node, "cve", "cve_id", "cveId"))
        val cvss = Nodes.double(node, "cvss", "cvss_score", "score")?.takeIf { it in 0.0..10.0 }
        val confidence = Confidence.from(Nodes.text(node, "confidence", "likelihood"))

        return Finding(
            fingerprint = fingerprint(title, method, url),
            title = title.take(220),
            severity = resolvedSeverity,
            confidence = confidence,
            url = url,
            method = method,
            description = description,
            stepsToReproduce = stepsToReproduce,
            impact = impact,
            poc = poc,
            pocType = pocType,
            evidence = evidence,
            remediation = remediation,
            cwe = cwe,
            cve = cve,
            cvss = cvss,
            skillId = skill.id,
            skillName = skill.name,
            source = "ai"
        )
    }

    private fun buildDescription(node: JsonNode): String {
        val base = Nodes.text(node, "description", "detail", "details", "summary").orEmpty()
        val scenario = Nodes.text(node, "attack_scenario", "scenario", "exploitation")
        return buildString {
            if (base.isNotBlank()) append(base.trim())
            if (!scenario.isNullOrBlank()) {
                if (isNotEmpty()) append("\n\n")
                append("Attack scenario: ").append(scenario.trim())
            }
        }.take(10000)
    }

    private fun normalizePocType(raw: String?, poc: String): String {
        val value = raw?.trim()?.lowercase()?.substringBefore(' ')
        if (!value.isNullOrBlank()) {
            return when {
                value.contains("html") -> "html"
                value.contains("python") || value.contains("py") -> "python"
                value.contains("curl") || value.contains("bash") || value.contains("shell") -> "curl"
                value == "none" || value == "null" || value == "text" -> "none"
                else -> "none"
            }
        }
        if (poc.isBlank()) return "none"
        val trimmed = poc.trim()
        return when {
            trimmed.startsWith("curl ") || trimmed.startsWith("curl\n") -> "curl"
            trimmed.contains("<!doctype html", true) || trimmed.contains("<html", true) -> "html"
            trimmed.contains("import requests") || trimmed.contains("#!/usr/bin/env python") ||
                trimmed.startsWith("import ") || trimmed.startsWith("from ") -> "python"
            else -> "none"
        }
    }

    private fun normalizeCve(value: String?): String {
        if (value.isNullOrBlank()) return ""
        val match = Regex("""(?i)CVE[-_\s]?(\d{4})[-_\s]?(\d{4,7})""").find(value)
        return when {
            match != null -> "CVE-${match.groupValues[1]}-${match.groupValues[2]}"
            else -> value.take(40)
        }
    }

    private fun normalizeCwe(value: String?): String {
        if (value.isNullOrBlank()) return ""
        val match = Regex("""(?i)CWE[-_\s]?(\d+)""").find(value)
        return when {
            match != null -> "CWE-${match.groupValues[1]}"
            value.all { it.isDigit() } -> "CWE-$value"
            else -> value.take(40)
        }
    }

    fun fingerprint(title: String, method: String, url: String): String {
        val normalizedUrl = normalizeUrl(url)
        val input = "${method.uppercase()}|$normalizedUrl|${title.lowercase().trim()}"
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return HexFormat.of().formatHex(digest).take(32)
    }

    fun normalizeUrl(url: String): String {
        var value = url.trim().substringBefore('#').lowercase()
        if (value.isBlank()) return ""
        value = Regex("""[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}""")
            .replace(value, "{uuid}")
        value = Regex("""/\d+(?=[/?#]|$)""").replace(value, "/{id}")
        value = Regex("""([?&][^=&#]+)=[^&#]*""").replace(value) { it.groupValues[1] + "={v}" }
        return value
    }

    private fun repairTrailingCommas(json: String): String =
        Regex(""",\s*([}\]])""").replace(json, "$1")

    /**
     * Finds the first complete JSON object/array in text, respecting strings
     * and escapes. Models occasionally wrap JSON in prose despite instructions.
     */
    fun extractJson(raw: String): String? {
        var text = raw.trim()
        val fence = Regex("```(?:json)?\\s*([\\s\\S]*?)```", RegexOption.IGNORE_CASE).find(text)
        if (fence != null) {
            text = fence.groupValues[1].trim()
        }

        val objStart = text.indexOf('{')
        val arrStart = text.indexOf('[')
        val start = when {
            objStart < 0 && arrStart < 0 -> return null
            objStart < 0 -> arrStart
            arrStart < 0 -> objStart
            else -> minOf(objStart, arrStart)
        }

        val end = balancedEnd(text, start)
        if (end != null) return text.substring(start, end + 1)

        val lastBrace = text.lastIndexOf('}')
        val lastBracket = text.lastIndexOf(']')
        val fallback = maxOf(lastBrace, lastBracket)
        if (fallback > start) return text.substring(start, fallback + 1)
        return null
    }

    private fun balancedEnd(text: String, start: Int): Int? {
        val stack = ArrayDeque<Char>()
        var inString = false
        var escaped = false
        for (i in start until text.length) {
            val c = text[i]
            if (inString) {
                if (escaped) {
                    escaped = false
                } else if (c == '\\') {
                    escaped = true
                } else if (c == '"') {
                    inString = false
                }
                continue
            }
            when (c) {
                '"' -> inString = true
                '{' -> stack.addLast('}')
                '[' -> stack.addLast(']')
                '}', ']' -> {
                    if (stack.isEmpty() || stack.removeLast() != c) return null
                    if (stack.isEmpty()) return i
                }
            }
        }
        return null
    }
}
