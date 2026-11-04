package io.sectiv.burp.scan

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.sectiv.burp.ai.FindingParser
import io.sectiv.burp.ai.LlmGateway
import io.sectiv.burp.ai.LlmClient
import io.sectiv.burp.ai.LlmException
import io.sectiv.burp.ai.PromptBuilder
import io.sectiv.burp.core.CapturedExchange
import io.sectiv.burp.core.Finding
import io.sectiv.burp.core.HttpTranscript
import io.sectiv.burp.core.IdentityContextParser
import io.sectiv.burp.core.IdentityPair
import io.sectiv.burp.core.ProviderConfig
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.Settings
import io.sectiv.burp.core.Severity
import io.sectiv.burp.core.Skill
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean

enum class ScanStage { PREPARING, AI_REVIEW, IDENTITY_SWAP, FINISHED }

enum class LogLevel { INFO, SUCCESS, WARN, ERROR }

data class ScanRequest(
    val exchanges: List<CapturedExchange>,
    val skills: List<Skill>,
    val authContext: String,
    val provider: ProviderConfig,
    val settings: Settings,
    val identitySwap: Boolean
)

data class ScanSummary(
    val addedFindings: Int,
    val duplicateFindings: Int,
    val aiCalls: Int,
    val failedAiCalls: Int,
    val swapRequests: Int,
    val skippedSwaps: Int,
    val cancelled: Boolean,
    val durationMs: Long
)

interface ScanListener {
    fun onLog(message: String, level: LogLevel)
    fun onProgress(stage: ScanStage, message: String, done: Int, total: Int)
    fun onFindingsAdded(count: Int)
    fun onFinished(summary: ScanSummary)
    fun onFailed(message: String, error: Throwable?)
}

class ScanHandle internal constructor(
    private val future: Future<*>,
    private val cancelled: AtomicBoolean
) {
    fun cancel() {
        cancelled.set(true)
        future.cancel(true)
    }

    val isCancelled: Boolean
        get() = cancelled.get()
}

/**
 * Runs the review on a background thread. The only requests this class sends
 * itself are deterministic identity swaps built from the tester's two
 * captured credentials; the model never gets to author arbitrary requests.
 */
class ScanEngine(
    private val api: MontoyaApi,
    private val store: SectivStore,
    private val llm: LlmGateway = LlmClient()
) {
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "sectiv-scan").apply { isDaemon = true }
    }
    private val running = AtomicBoolean(false)

    fun scan(request: ScanRequest, listener: ScanListener): ScanHandle {
        check(request.exchanges.isNotEmpty()) { "Select at least one request to review." }
        check(request.skills.isNotEmpty()) { "Select at least one skill." }
        check(!running.getAndSet(true)) { "A scan is already running." }

        val cancelled = AtomicBoolean(false)
        val future = executor.submit {
            val started = System.currentTimeMillis()
            try {
                execute(request, listener, cancelled, started)
            } catch (e: LlmException) {
                if (cancelled.get()) {
                    listener.onFinished(
                        ScanSummary(0, 0, 0, 0, 0, 0, true, System.currentTimeMillis() - started)
                    )
                } else {
                    listener.onFailed(e.message ?: "Scan failed.", e)
                }
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                listener.onFinished(
                    ScanSummary(0, 0, 0, 0, 0, 0, true, System.currentTimeMillis() - started)
                )
            } catch (e: Exception) {
                listener.onFailed(e.message ?: e.javaClass.simpleName, e)
            } finally {
                running.set(false)
            }
        }
        return ScanHandle(future, cancelled)
    }

    private fun execute(
        request: ScanRequest,
        listener: ScanListener,
        cancelled: AtomicBoolean,
        started: Long
    ) {
        val identities = IdentityContextParser.parse(request.authContext)
        listener.onLog("Provider: ${request.provider.name} · ${request.provider.model}", LogLevel.INFO)
        if (identities.hasAnyIdentity) {
            listener.onLog("Identities: ${identities.summary()}", LogLevel.INFO)
        } else {
            listener.onLog("No structured identities detected in the context box. AI review still runs; active checks are unavailable.", LogLevel.WARN)
        }

        var added = 0
        var duplicates = 0
        var aiCalls = 0
        var failedCalls = 0

        // The identity box is tester notes, not captured traffic, but it can
        // contain live cookies. Mask it with the same rules before prompting.
        val promptAuthContext = if (request.settings.maskSecrets) {
            HttpTranscript.redact(request.authContext, identities, true)
        } else {
            request.authContext
        }

        val prompts = request.skills.associateWith { skill ->
            PromptBuilder.build(skill, request.exchanges, request.settings, identities, promptAuthContext)
        }
        val totalChunks = prompts.values.sumOf { it.chunks.size }
        listener.onLog("Packed ${request.exchanges.size} exchanges into $totalChunks AI call(s).", LogLevel.INFO)

        var chunkDone = 0
        for ((skill, prompt) in prompts) {
            if (cancelled.get()) break
            listener.onLog("Review goal: ${skill.name}", LogLevel.INFO)
            if (prompt.chunks.isEmpty()) {
                listener.onLog("No traffic to review for ${skill.name}.", LogLevel.WARN)
                continue
            }
            for ((index, chunk) in prompt.chunks.withIndex()) {
                if (cancelled.get()) break
                listener.onProgress(
                    ScanStage.AI_REVIEW,
                    "Reviewing ${skill.name} · chunk ${index + 1}/${prompt.chunks.size}",
                    chunkDone,
                    totalChunks
                )
                val user = PromptBuilder.userPrompt(skill.name, promptAuthContext, chunk, index, prompt.chunks.size)
                aiCalls++
                try {
                    val reply = llm.complete(
                        request.provider,
                        prompt.system,
                        user,
                        cancel = { cancelled.get() }
                    )
                    val usage = reply.usage.summary()
                    var parsed = FindingParser.parse(reply.text, skill, request.settings.maxFindingsPerChunk)

                    if (parsed.error != null) {
                        listener.onLog("Model output could not be parsed (${parsed.error}); asking once for a clean JSON response.", LogLevel.WARN)
                        val retry = llm.complete(
                            request.provider,
                            prompt.system,
                            user + "\n\nREMINDER: Your previous answer was not valid JSON. Return ONLY the JSON object described above, with no prose or code fences.",
                            cancel = { cancelled.get() }
                        )
                        aiCalls++
                        parsed = FindingParser.parse(retry.text, skill, request.settings.maxFindingsPerChunk)
                    }

                    if (parsed.error != null) {
                        failedCalls++
                        listener.onLog("Skipping chunk: ${parsed.error}", LogLevel.ERROR)
                    } else {
                        val enriched = parsed.findings.map { enrich(it, request.exchanges) }
                        val inserted = store.addFindings(enriched)
                        added += inserted
                        duplicates += enriched.size - inserted
                        parsed.notes.forEach { listener.onLog(it, LogLevel.INFO) }
                        if (inserted > 0) {
                            listener.onFindingsAdded(inserted)
                            listener.onLog(
                                "${inserted} finding(s) from ${skill.name} chunk ${index + 1}${usage.let { if (it.isNotBlank()) " ($it)" else "" }}",
                                LogLevel.SUCCESS
                            )
                        } else if (enriched.isNotEmpty()) {
                            listener.onLog("Only duplicate findings in ${skill.name} chunk ${index + 1}.", LogLevel.INFO)
                        } else {
                            listener.onLog("No supported findings in ${skill.name} chunk ${index + 1}.", LogLevel.INFO)
                        }
                    }
                } catch (e: LlmException) {
                    if (cancelled.get()) break
                    failedCalls++
                    listener.onLog(e.message ?: "AI request failed.", LogLevel.ERROR)
                }
                chunkDone++
                listener.onProgress(
                    ScanStage.AI_REVIEW,
                    "Reviewed ${skill.name} · chunk ${index + 1}/${prompt.chunks.size}",
                    chunkDone,
                    totalChunks
                )
            }
        }

        var swapRequests = 0
        var skippedSwaps = 0
        if (!cancelled.get() && request.identitySwap) {
            val result = runIdentityChecks(request, identities, listener, cancelled, started)
            added += result.first
            swapRequests = result.second
            skippedSwaps = result.third
        }

        listener.onProgress(ScanStage.FINISHED, "Scan complete", 1, 1)
        val summary = ScanSummary(
            addedFindings = added,
            duplicateFindings = duplicates,
            aiCalls = aiCalls,
            failedAiCalls = failedCalls,
            swapRequests = swapRequests,
            skippedSwaps = skippedSwaps,
            cancelled = cancelled.get(),
            durationMs = System.currentTimeMillis() - started
        )
        listener.onFinished(summary)
    }

    private fun runIdentityChecks(
        request: ScanRequest,
        identities: IdentityPair,
        listener: ScanListener,
        cancelled: AtomicBoolean,
        started: Long
    ): Triple<Int, Int, Int> {
        if (!identities.swappable) {
            listener.onLog("Identity swap skipped: add a Cookie or Authorization value for both User A and User B.", LogLevel.WARN)
            return Triple(0, 0, 0)
        }

        val allowedMethods = if (request.settings.allowStateChangingChecks) {
            setOf("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
        } else {
            setOf("GET", "HEAD", "OPTIONS")
        }
        val candidates = request.exchanges
            .filter { it.status in 200..299 }
            .filter { it.method.uppercase() in allowedMethods }
            .take(request.settings.maxSwapRequests.coerceIn(1, 200))

        if (candidates.isEmpty()) {
            listener.onLog("Identity swap skipped: no eligible success responses in scope (state-changing methods are disabled in Settings).", LogLevel.WARN)
            return Triple(0, 0, 0)
        }

        listener.onLog("Running identity-swap checks on ${candidates.size} request(s).", LogLevel.WARN)
        var sent = 0
        var added = 0
        var skipped = 0

        for ((index, exchange) in candidates.withIndex()) {
            if (cancelled.get()) break
            listener.onProgress(
                ScanStage.IDENTITY_SWAP,
                "Identity swap ${index + 1}/${candidates.size} · ${exchange.method} ${exchange.path}",
                index,
                candidates.size
            )
            val swap = IdentitySwap.buildRequest(exchange.requestRaw, identities)
            if (swap == null) {
                skipped++
                listener.onLog("Skipped ${exchange.method} ${exchange.path}: no matching User A credential in the request.", LogLevel.INFO)
                continue
            }

            try {
                val service = HttpService.httpService(exchange.host, exchange.port, exchange.secure)
                val testRequest = HttpRequest.httpRequest(service, swap.raw)
                val response = api.http().sendRequest(testRequest)
                sent++
                if (response.response() == null) {
                    listener.onLog("No response for ${exchange.method} ${exchange.path}; skipped.", LogLevel.WARN)
                    continue
                }
                val status = response.response().statusCode().toInt()
                val body = response.response().bodyToString()
                val verdict = IdentitySwap.evaluate(exchange, status, body, identities)

                if (verdict.vulnerable) {
                    val finding = buildSwapFinding(exchange, swap, verdict, status, body)
                    val inserted = store.addFindings(listOf(finding))
                    if (inserted > 0) {
                        added++
                        listener.onFindingsAdded(1)
                        listener.onLog(
                            "Potential cross-identity access at ${exchange.method} ${exchange.path} · HTTP $status, ${(verdict.similarity * 100).toInt()}% similar",
                            LogLevel.SUCCESS
                        )
                    } else {
                        listener.onLog("Cross-identity result at ${exchange.path} duplicates an existing finding.", LogLevel.INFO)
                    }
                } else {
                    listener.onLog("Identity swap held at ${exchange.method} ${exchange.path}: ${verdict.reason}", LogLevel.INFO)
                }
            } catch (e: Exception) {
                listener.onLog("Identity swap failed for ${exchange.path}: ${e.message}", LogLevel.WARN)
            }

            val delay = request.settings.requestDelayMs.coerceIn(0, 5000)
            if (delay > 0) {
                var slept = 0
                while (slept < delay && !cancelled.get()) {
                    Thread.sleep(minOf(100, delay - slept).toLong())
                    slept += 100
                }
            }
        }

        listener.onProgress(ScanStage.IDENTITY_SWAP, "Identity checks complete", candidates.size, candidates.size)
        listener.onLog(
            "Identity checks: $sent sent, $added finding(s), $skipped skipped. Elapsed ${(System.currentTimeMillis() - started) / 1000}s.",
            LogLevel.INFO
        )
        return Triple(added, sent, skipped)
    }

    private fun buildSwapFinding(
        exchange: CapturedExchange,
        swap: SwapRequest,
        verdict: SwapVerdict,
        status: Int,
        body: String
    ): Finding {
        val title = "Cross-identity access at ${exchange.method} ${exchange.path}"
        return Finding(
            fingerprint = FindingParser.fingerprint(title, exchange.method, exchange.url),
            title = title,
            severity = Severity.HIGH,
            confidence = verdict.confidence,
            url = exchange.url,
            method = exchange.method,
            host = exchange.host,
            port = exchange.port,
            secure = exchange.secure,
            description = buildString {
                append("Replaying the captured request with User A's session replaced by User B's returned HTTP $status and a response that is ")
                append((verdict.similarity * 100).toInt()).append("% similar to the User A response. ")
                append("This strongly suggests the endpoint does not verify that the authenticated caller owns the requested object.\n\n")
                append("This is an active check performed by Sectiv using the two identities from the context box. ")
                append("Manually confirm that the returned data belongs to User A and not to a shared or public resource before reporting it to the client.")
            },
            evidence = buildString {
                append(verdict.reason)
                append("\n\nSwapped headers: ").append(swap.replaced.joinToString(", "))
                append("\nRequest as User B:\n").append(HttpClip.clip(swap.raw, 2500))
                append("\n\nResponse (HTTP $status):\n").append(HttpClip.clip(body, 1500))
            },
            remediation = "Enforce object-level authorization on the server for every object access. Derive the object owner from the authenticated session and reject requests where the caller does not own the object (return 403/404). Do not rely on unguessable identifiers as the only control.",
            cwe = "CWE-639",
            cvss = 8.1,
            skillId = "active-identity-swap",
            skillName = "Identity swap verification",
            source = "identity-swap",
            requestRaw = HttpClip.clip(swap.raw, 12000),
            responseRaw = HttpClip.clip("HTTP $status\n\n$body", 12000)
        )
    }

    private fun enrich(finding: Finding, exchanges: List<CapturedExchange>): Finding {
        val match = matchExchange(finding, exchanges) ?: return finding
        return finding.copy(
            url = finding.url.ifBlank { match.url },
            method = finding.method.ifBlank { match.method },
            host = finding.host.ifBlank { match.host },
            port = if (finding.host.isBlank()) match.port else finding.port,
            secure = if (finding.host.isBlank()) match.secure else finding.secure,
            requestRaw = finding.requestRaw.ifBlank { HttpClip.clip(match.requestRaw, 12000) },
            responseRaw = finding.responseRaw.ifBlank { HttpClip.clip(match.responseRaw, 12000) }
        )
    }

    private fun matchExchange(finding: Finding, exchanges: List<CapturedExchange>): CapturedExchange? {
        val url = finding.url.trim()
        if (url.isNotEmpty()) {
            exchanges.firstOrNull { it.url.equals(url, ignoreCase = true) }?.let { return it }
            val normalized = FindingParser.normalizeUrl(url)
            exchanges.firstOrNull { FindingParser.normalizeUrl(it.url) == normalized }?.let { return it }
            val hostAndPath = runCatching {
                val uri = java.net.URI(url)
                (uri.host ?: "") to uri.rawPath.orEmpty()
            }.getOrNull()
            if (hostAndPath != null) {
                exchanges.firstOrNull {
                    it.host.equals(hostAndPath.first, ignoreCase = true) &&
                        it.path.substringBefore('?').equals(hostAndPath.second, ignoreCase = true)
                }?.let { return it }
            }
        }
        return if (exchanges.size == 1) exchanges.first() else null
    }

    fun shutdown() {
        executor.shutdownNow()
    }
}

private object HttpClip {
    fun clip(text: String, max: Int): String {
        if (text.length <= max) return text
        return text.take(max - 80) + "\n...[truncated ${text.length - max + 80} chars]"
    }
}
