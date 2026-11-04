package io.sectiv.burp.report

import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.FindingStatus
import io.sectiv.burp.core.Json
import io.sectiv.burp.core.Severity
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

data class ReportMeta(
    val title: String = "Sectiv Security Review",
    val target: String = "",
    val provider: String = "",
    val generatedAt: Long = System.currentTimeMillis()
)

object ReportWriter {

    private val dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z")
        .withZone(ZoneId.systemDefault())

    fun sort(findings: List<Finding>): List<Finding> =
        findings.sortedWith(compareBy<Finding> { it.severity.rank }.thenByDescending { it.createdAt })

    fun toJson(findings: List<Finding>, meta: ReportMeta): String {
        val sorted = sort(findings)
        val counts = summary(sorted)
        val payload = linkedMapOf(
            "report" to linkedMapOf(
                "title" to meta.title,
                "target" to meta.target,
                "provider" to meta.provider,
                "generatedAt" to dateFormat.format(Instant.ofEpochMilli(meta.generatedAt))
            ),
            "summary" to linkedMapOf(
                "critical" to (counts[Severity.CRITICAL] ?: 0),
                "high" to (counts[Severity.HIGH] ?: 0),
                "medium" to (counts[Severity.MEDIUM] ?: 0),
                "low" to (counts[Severity.LOW] ?: 0),
                "info" to (counts[Severity.INFO] ?: 0),
                "total" to sorted.size
            ),
            "findings" to sorted.map { finding ->
                linkedMapOf(
                    "id" to finding.id,
                    "title" to finding.title,
                    "severity" to finding.severity.label,
                    "confidence" to finding.confidence.label,
                    "status" to finding.status.label,
                    "url" to finding.url,
                    "method" to finding.method,
                    "description" to finding.description,
                    "stepsToReproduce" to finding.stepsToReproduce,
                    "impact" to finding.impact,
                    "poc" to finding.poc,
                    "pocType" to finding.pocType,
                    "evidence" to finding.evidence,
                    "remediation" to finding.remediation,
                    "cwe" to finding.cwe,
                    "cve" to finding.cve,
                    "cvss" to finding.cvss,
                    "skill" to finding.skillName,
                    "source" to finding.source,
                    "createdAt" to dateFormat.format(Instant.ofEpochMilli(finding.createdAt))
                )
            }
        )
        return Json.writePretty(payload)
    }

    fun toMarkdown(findings: List<Finding>, meta: ReportMeta): String {
        val sorted = sort(findings)
        val counts = summary(sorted)
        return buildString {
            appendLine("# ${meta.title}")
            appendLine()
            if (meta.target.isNotBlank()) appendLine("**Target:** ${meta.target}  ")
            if (meta.provider.isNotBlank()) appendLine("**AI provider:** ${meta.provider}  ")
            appendLine("**Generated:** ${dateFormat.format(Instant.ofEpochMilli(meta.generatedAt))}")
            appendLine()
            appendLine("## Summary")
            appendLine()
            appendLine("| Severity | Count |")
            appendLine("| --- | ---: |")
            for (severity in Severity.entries) {
                appendLine("| ${severity.label} | ${counts[severity] ?: 0} |")
            }
            appendLine("| **Total** | **${sorted.size}** |")
            appendLine()

            if (sorted.isEmpty()) {
                appendLine("No findings were recorded.")
                return@buildString
            }

            appendLine("## Findings")
            appendLine()
            for ((index, finding) in sorted.withIndex()) {
                appendLine("### ${index + 1}. ${finding.title}")
                appendLine()
                appendLine("- **Severity:** ${finding.severity.label}")
                appendLine("- **Confidence:** ${finding.confidence.label}")
                appendLine("- **Status:** ${finding.status.label}")
                if (finding.method.isNotBlank() || finding.url.isNotBlank()) {
                    appendLine("- **Endpoint:** `${finding.method} ${finding.url}`")
                }
                if (finding.cwe.isNotBlank()) appendLine("- **Weakness:** ${finding.cwe}")
                if (finding.cve.isNotBlank()) appendLine("- **CVE:** ${finding.cve}")
                finding.cvss?.let { appendLine("- **CVSS:** $it") }
                if (finding.skillName.isNotBlank()) appendLine("- **Skill:** ${finding.skillName}")
                if (finding.source == "identity-swap") appendLine("- **Source:** Active identity-swap check")
                appendLine()
                if (finding.description.isNotBlank()) {
                    appendLine("#### Description")
                    appendLine()
                    appendLine(finding.description.trim())
                    appendLine()
                }
                if (finding.stepsToReproduce.isNotBlank()) {
                    appendLine("#### Steps to Reproduce")
                    appendLine()
                    appendLine(finding.stepsToReproduce.trim())
                    appendLine()
                }
                if (finding.impact.isNotBlank()) {
                    appendLine("#### Impact")
                    appendLine()
                    appendLine(finding.impact.trim())
                    appendLine()
                }
                if (finding.evidence.isNotBlank()) {
                    appendLine("#### Evidence")
                    appendLine()
                    appendLine("~~~")
                    appendLine(finding.evidence.trim())
                    appendLine("~~~")
                    appendLine()
                }
                if (finding.poc.isNotBlank()) {
                    val pocTitle = when (finding.pocType.lowercase()) {
                        "html" -> "#### Proof of Concept (HTML page)"
                        "python" -> "#### Proof of Concept (Python)"
                        "curl" -> "#### Proof of Concept (curl)"
                        else -> "#### Proof of Concept"
                    }
                    appendLine(pocTitle)
                    appendLine()
                    appendLine("~~~")
                    appendLine(finding.poc.trim())
                    appendLine("~~~")
                    appendLine()
                }
                if (finding.remediation.isNotBlank()) {
                    appendLine("#### Remediation")
                    appendLine()
                    appendLine(finding.remediation.trim())
                    appendLine()
                }
                appendLine("---")
                appendLine()
            }
        }
    }

    fun toHtml(findings: List<Finding>, meta: ReportMeta): String {
        val sorted = sort(findings)
        val counts = summary(sorted)
        val e = Json::escapeHtml
        return buildString {
            appendLine("<!doctype html>")
            appendLine("<html lang=\"en\"><head><meta charset=\"utf-8\">")
            appendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
            appendLine("<title>${e(meta.title)}</title>")
            appendLine(
                """
                <style>
                :root { --bg:#f5f7fb; --card:#ffffff; --ink:#172033; --muted:#5f6b82; --line:#e1e6f0; --accent:#3457d5; }
                * { box-sizing:border-box; }
                body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
                .wrap { max-width:1000px; margin:0 auto; padding:36px 24px 80px; }
                header { margin-bottom:26px; }
                .kicker { color:var(--accent); font-weight:700; letter-spacing:.08em; text-transform:uppercase; font-size:11px; }
                h1 { font-size:32px; margin:6px 0 8px; letter-spacing:-.02em; }
                .meta { color:var(--muted); font-size:13px; }
                .meta span { margin-right:16px; }
                .cards { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:26px 0 30px; }
                .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
                .card .n { font-size:26px; font-weight:750; line-height:1; }
                .card .l { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.07em; margin-top:6px; }
                .critical { border-top:3px solid #d32f2f; } .high { border-top:3px solid #e86a12; }
                .medium { border-top:3px solid #c89400; } .low { border-top:3px solid #1f8b4c; }
                .info { border-top:3px solid #607d8b; } .total { border-top:3px solid var(--accent); }
                .finding { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:22px 24px; margin:0 0 16px; }
                .finding h2 { font-size:19px; margin:0 0 10px; }
                .pill { display:inline-block; border-radius:999px; padding:2px 10px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }
                .pill.critical { background:#fdecec; color:#b71c1c; border-top:0; } .pill.high { background:#fff1e5; color:#ad4e00; border-top:0; }
                .pill.medium { background:#fff8db; color:#7a5b00; border-top:0; } .pill.low { background:#e8f6ee; color:#146c3a; border-top:0; }
                .pill.info { background:#eef2f5; color:#455a64; border-top:0; }
                dl { display:grid; grid-template-columns:130px 1fr; gap:6px 14px; margin:12px 0 18px; font-size:13px; }
                dt { color:var(--muted); } dd { margin:0; word-break:break-word; }
                h3 { font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:18px 0 6px; }
                pre { background:#0f1728; color:#d9e2f2; padding:14px 16px; border-radius:10px; overflow:auto; font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; white-space:pre-wrap; word-break:break-word; }
                .empty { background:var(--card); border:1px dashed var(--line); border-radius:14px; padding:40px; text-align:center; color:var(--muted); }
                @media print { body { background:#fff; } .finding { break-inside:avoid; } }
                @media (max-width:700px) { .cards { grid-template-columns:repeat(2,1fr); } dl { grid-template-columns:1fr; } }
                </style>
                """.trimIndent()
            )
            appendLine("</head><body><div class=\"wrap\">")
            appendLine("<header><div class=\"kicker\">Sectiv · AI-assisted security review</div>")
            appendLine("<h1>${e(meta.title)}</h1><div class=\"meta\">")
            if (meta.target.isNotBlank()) appendLine("<span><strong>Target:</strong> ${e(meta.target)}</span>")
            if (meta.provider.isNotBlank()) appendLine("<span><strong>Provider:</strong> ${e(meta.provider)}</span>")
            appendLine("<span><strong>Generated:</strong> ${e(dateFormat.format(Instant.ofEpochMilli(meta.generatedAt)))}</span>")
            appendLine("</div></header>")

            appendLine("<div class=\"cards\">")
            for (severity in Severity.entries) {
                appendLine("<div class=\"card ${severity.name.lowercase()}\"><div class=\"n\">${counts[severity] ?: 0}</div><div class=\"l\">${severity.label}</div></div>")
            }
            appendLine("<div class=\"card total\"><div class=\"n\">${sorted.size}</div><div class=\"l\">Total</div></div>")
            appendLine("</div>")

            if (sorted.isEmpty()) {
                appendLine("<div class=\"empty\">No findings were recorded for this review.</div>")
            } else {
                appendLine("<h2 style=\"font-size:14px;text-transform:uppercase;letter-spacing:.07em;color:#5f6b82\">Findings</h2>")
                for (finding in sorted) {
                    appendLine("<section class=\"finding\">")
                    appendLine("<span class=\"pill ${finding.severity.name.lowercase()}\">${finding.severity.label}</span>")
                    appendLine("<h2>${e(finding.title)}</h2>")
                    appendLine("<dl>")
                    appendLine("<dt>Confidence</dt><dd>${e(finding.confidence.label)}</dd>")
                    appendLine("<dt>Status</dt><dd>${e(finding.status.label)}</dd>")
                    if (finding.method.isNotBlank() || finding.url.isNotBlank()) {
                        appendLine("<dt>Endpoint</dt><dd><code>${e(finding.method)} ${e(finding.url)}</code></dd>")
                    }
                    if (finding.cwe.isNotBlank()) appendLine("<dt>Weakness</dt><dd>${e(finding.cwe)}</dd>")
                    if (finding.cve.isNotBlank()) appendLine("<dt>CVE</dt><dd>${e(finding.cve)}</dd>")
                    finding.cvss?.let { appendLine("<dt>CVSS</dt><dd>$it</dd>") }
                    if (finding.skillName.isNotBlank()) appendLine("<dt>Skill</dt><dd>${e(finding.skillName)}</dd>")
                    appendLine("<dt>Source</dt><dd>${if (finding.source == "identity-swap") "Active identity-swap check" else "AI review"}</dd>")
                    appendLine("</dl>")
                    if (finding.description.isNotBlank()) {
                        appendLine("<h3>Description</h3><p>${e(finding.description).replace("\n", "<br>")}</p>")
                    }
                    if (finding.stepsToReproduce.isNotBlank()) {
                        appendLine("<h3>Steps to Reproduce</h3><p>${e(finding.stepsToReproduce).replace("\n", "<br>")}</p>")
                    }
                    if (finding.impact.isNotBlank()) {
                        appendLine("<h3>Impact</h3><p>${e(finding.impact).replace("\n", "<br>")}</p>")
                    }
                    if (finding.evidence.isNotBlank()) {
                        appendLine("<h3>Evidence</h3><pre>${e(finding.evidence)}</pre>")
                    }
                    if (finding.poc.isNotBlank()) {
                        val pocTitle = when (finding.pocType.lowercase()) {
                            "html" -> "Proof of Concept (HTML page)"
                            "python" -> "Proof of Concept (Python)"
                            "curl" -> "Proof of Concept (curl)"
                            else -> "Proof of Concept"
                        }
                        appendLine("<h3>${e(pocTitle)}</h3><pre>${e(finding.poc)}</pre>")
                    }
                    if (finding.remediation.isNotBlank()) {
                        appendLine("<h3>Remediation</h3><p>${e(finding.remediation).replace("\n", "<br>")}</p>")
                    }
                    appendLine("</section>")
                }
            }
            appendLine("</div></body></html>")
        }
    }

    private fun summary(findings: List<Finding>): Map<Severity, Int> =
        Severity.entries.associateWith { severity -> findings.count { it.severity == severity } }

    fun openFindings(findings: List<Finding>): Int =
        findings.count { it.status == FindingStatus.OPEN }
}
