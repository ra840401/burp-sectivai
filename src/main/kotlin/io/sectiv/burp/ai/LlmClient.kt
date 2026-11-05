package io.sectiv.burp.ai

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ObjectNode
import io.sectiv.burp.core.Json
import io.sectiv.burp.core.Nodes
import io.sectiv.burp.core.ProviderConfig
import io.sectiv.burp.core.ProviderKind
import io.sectiv.burp.core.Text
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpConnectTimeoutException
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

data class LlmUsage(
    val promptTokens: Int? = null,
    val completionTokens: Int? = null
) {
    fun summary(): String {
        if (promptTokens == null && completionTokens == null) return ""
        return buildList {
            promptTokens?.let { add("in $it") }
            completionTokens?.let { add("out $it") }
        }.joinToString(", ", prefix = "tokens: ")
    }
}

data class LlmReply(
    val text: String,
    val usage: LlmUsage = LlmUsage()
)

class LlmException(
    message: String,
    val retryable: Boolean = false
) : Exception(message)

interface LlmGateway {
    fun complete(
        provider: ProviderConfig,
        system: String,
        user: String,
        cancel: () -> Boolean = { false },
        maxAttempts: Int = 3,
        allowEmpty: Boolean = false
    ): LlmReply

    fun ping(provider: ProviderConfig): String
}

/**
 * Minimal, dependency-free HTTP client for OpenAI-compatible chat completions
 * and the Anthropic Messages API. Keeps the extension compatible with
 * DeepSeek, OpenAI, GLM, z.ai, OpenRouter, Ollama, LM Studio and anything else
 * exposing /v1/chat/completions.
 */
class LlmClient(
    private val http: HttpClient = defaultHttpClient()
) : LlmGateway {

    override fun complete(
        provider: ProviderConfig,
        system: String,
        user: String,
        cancel: () -> Boolean,
        maxAttempts: Int,
        allowEmpty: Boolean
    ): LlmReply {
        validate(provider)
        if (cancel()) throw LlmException("Scan cancelled.")
        val body = buildBody(provider, system, user)
        var attempt = 0
        var lastError: Exception? = null
        while (attempt < maxAttempts) {
            if (cancel()) throw LlmException("Scan cancelled.")
            attempt++
            try {
                val response = post(provider, body, cancel)
                val status = response.statusCode()
                val payload = response.body().orEmpty()
                if (status in 200..299) {
                    return parseReply(provider, payload, allowEmpty)
                }
                val message = extractError(payload)
                    ?: "HTTP $status from ${provider.name}"
                val retryable = status == 408 || status == 409 || status == 429 || status >= 500
                if (retryable && attempt < maxAttempts) {
                    sleep(backoffMillis(attempt, response), cancel)
                    continue
                }
                throw LlmException(friendlyError(provider, status, message), retryable)
            } catch (e: LlmException) {
                lastError = e
                if (!e.retryable || attempt >= maxAttempts) throw e
                sleep(backoffMillis(attempt, null), cancel)
            } catch (e: HttpConnectTimeoutException) {
                lastError = e
                if (attempt >= maxAttempts) {
                    throw LlmException(
                        "Could not connect to ${provider.name}: connection timed out. Check your proxy/VPN, firewall and DNS, or verify the base URL.",
                        retryable = true
                    )
                }
                sleep(backoffMillis(attempt, null), cancel)
            } catch (e: HttpTimeoutException) {
                lastError = e
                if (attempt >= maxAttempts) {
                    throw LlmException(
                        "Request to ${provider.name} timed out after ${provider.timeoutSeconds}s. Increase the timeout in Settings, use a smaller chunk size, or check your proxy/VPN and base URL.",
                        retryable = true
                    )
                }
                sleep(backoffMillis(attempt, null), cancel)
            } catch (e: java.io.IOException) {
                lastError = e
                if (attempt >= maxAttempts) {
                    throw LlmException("Could not reach ${provider.name}: ${e.message ?: e.javaClass.simpleName}", retryable = true)
                }
                sleep(backoffMillis(attempt, null), cancel)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw LlmException("Scan cancelled.")
            }
        }
        throw LlmException(lastError?.message ?: "Unknown error calling ${provider.name}.")
    }

    override fun ping(provider: ProviderConfig): String {
        validate(provider)
        val testProvider = provider.copy(
            maxTokens = minOf(provider.maxTokens.coerceAtLeast(1), 64),
            temperature = null
        )
        val reply = complete(
            testProvider,
            "You are a connectivity test. Answer with one short sentence.",
            "Reply with exactly: OK",
            maxAttempts = 2,
            allowEmpty = true
        )
        return reply.text.ifBlank { "Connected" }
    }

    private fun validate(provider: ProviderConfig) {
        if (provider.baseUrl.isBlank()) {
            throw LlmException("No base URL configured for ${provider.name}.")
        }
        if (provider.model.isBlank()) {
            throw LlmException("No model configured for ${provider.name}.")
        }
        if (provider.requiresApiKey && provider.apiKey.isBlank()) {
            throw LlmException("No API key configured for ${provider.name}. Add one in Settings.")
        }
        val uri = try {
            URI.create(provider.baseUrl)
        } catch (e: Exception) {
            throw LlmException("Invalid base URL for ${provider.name}: ${provider.baseUrl}")
        }
        if (uri.scheme != "http" && uri.scheme != "https") {
            throw LlmException("Base URL for ${provider.name} must start with http:// or https://.")
        }
    }

    private fun buildBody(provider: ProviderConfig, system: String, user: String): String {
        val root: ObjectNode = Json.mapper.createObjectNode()
        root.put("model", provider.model.trim())

        when (provider.kind) {
            ProviderKind.ANTHROPIC -> {
                root.put("system", system)
                root.put("max_tokens", provider.maxTokens.coerceAtLeast(1))
                val messages = root.putArray("messages")
                messages.addObject()
                    .put("role", "user")
                    .put("content", user)
            }
            ProviderKind.OPENAI -> {
                val messages = root.putArray("messages")
                messages.addObject()
                    .put("role", "system")
                    .put("content", system)
                messages.addObject()
                    .put("role", "user")
                    .put("content", user)
                val tokenField = provider.maxTokensField.ifBlank { "max_tokens" }
                root.put(tokenField, provider.maxTokens.coerceAtLeast(1))
            }
        }

        provider.temperature?.let { root.put("temperature", it) }
        root.put("stream", false)

        if (provider.extraBodyJson.isNotBlank()) {
            try {
                val extra = Json.parseTree(provider.extraBodyJson)
                if (extra.isObject) {
                    extra.fields().forEach { (key, value) -> root.set<JsonNode>(key, value) }
                }
            } catch (e: Exception) {
                throw LlmException("Extra body JSON is invalid: ${e.message}")
            }
        }
        return root.toString()
    }

    private fun post(
        provider: ProviderConfig,
        body: String,
        cancel: () -> Boolean
    ): HttpResponse<String> {
        val timeout = provider.timeoutSeconds.coerceIn(15, 900)
        val builder = HttpRequest.newBuilder(URI.create(provider.baseUrl.trim()))
            .timeout(Duration.ofSeconds(timeout.toLong()))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body, Charsets.UTF_8))

        provider.extraHeaders.forEach { (name, value) ->
            if (name.isNotBlank() && value.isNotBlank() &&
                !name.equals("content-type", true) && !name.equals("authorization", true)
            ) {
                builder.header(name, value)
            }
        }

        if (provider.apiKey.isNotBlank()) {
            when (provider.kind) {
                ProviderKind.OPENAI -> builder.header("Authorization", "Bearer ${provider.apiKey.trim()}")
                ProviderKind.ANTHROPIC -> {
                    builder.header("x-api-key", provider.apiKey.trim())
                    builder.header("anthropic-version", "2023-06-01")
                }
            }
        }

        val future: CompletableFuture<HttpResponse<String>> =
            http.sendAsync(builder.build(), HttpResponse.BodyHandlers.ofString(Charsets.UTF_8))
        return await(future, timeout.toLong(), cancel)
    }

    private fun await(
        future: CompletableFuture<HttpResponse<String>>,
        timeoutSeconds: Long,
        cancel: () -> Boolean
    ): HttpResponse<String> {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds + 5)
        while (true) {
            if (cancel()) {
                future.cancel(true)
                throw LlmException("Scan cancelled.")
            }
            try {
                return future.get(150, TimeUnit.MILLISECONDS)
            } catch (_: TimeoutException) {
                if (System.nanoTime() > deadline) {
                    future.cancel(true)
                    throw HttpTimeoutException("Request timed out after ${timeoutSeconds}s")
                }
            } catch (_: java.util.concurrent.CancellationException) {
                throw LlmException("Scan cancelled.")
            } catch (e: InterruptedException) {
                future.cancel(true)
                Thread.currentThread().interrupt()
                throw e
            } catch (e: ExecutionException) {
                val cause = e.cause
                when (cause) {
                    is HttpTimeoutException -> throw cause
                    is java.io.IOException -> throw cause
                    is RuntimeException -> throw cause
                    else -> throw java.io.IOException(cause?.message ?: "Request failed", cause)
                }
            }
        }
    }

    private fun parseReply(provider: ProviderConfig, payload: String, allowEmpty: Boolean = false): LlmReply {
        val root = try {
            Json.parseTree(payload)
        } catch (e: Exception) {
            throw LlmException("${provider.name} returned a non-JSON response.")
        }

        return when (provider.kind) {
            ProviderKind.OPENAI -> {
                val choice = root.path("choices").firstOrNull()
                    ?: throw LlmException("${provider.name} returned no choices. ${extractError(payload) ?: ""}".trim())
                val contentNode = Nodes.field(choice, "message")?.let { Nodes.field(it, "content") }
                    ?: Nodes.field(choice, "text")
                    ?: Nodes.field(choice, "content")
                val text = contentToText(contentNode)
                if (text.isBlank()) {
                    val finish = Nodes.text(choice, "finish_reason")
                    if (finish == "length") {
                        throw LlmException("The model hit its output token limit before returning findings. Increase max output tokens in Settings.")
                    }
                    if (!allowEmpty) throw LlmException("${provider.name} returned an empty message.")
                }
                val usage = root.path("usage")
                LlmReply(
                    text = text,
                    usage = LlmUsage(
                        promptTokens = Nodes.field(usage, "prompt_tokens")?.asInt(),
                        completionTokens = Nodes.field(usage, "completion_tokens")?.asInt()
                    )
                )
            }
            ProviderKind.ANTHROPIC -> {
                val content = root.path("content")
                val text = if (content.isArray) {
                    content.mapNotNull { block ->
                        if (Nodes.text(block, "type") == "text") Nodes.text(block, "text") else null
                    }.joinToString("\n")
                } else {
                    Nodes.text(root, "content").orEmpty()
                }
                if (text.isBlank()) {
                    val stop = Nodes.text(root, "stop_reason")
                    if (stop == "max_tokens") {
                        throw LlmException("Claude hit its output token limit before returning findings. Increase max output tokens in Settings.")
                    }
                    if (!allowEmpty) throw LlmException("Claude returned an empty message.")
                }
                val usage = root.path("usage")
                LlmReply(
                    text = text,
                    usage = LlmUsage(
                        promptTokens = Nodes.field(usage, "input_tokens")?.asInt(),
                        completionTokens = Nodes.field(usage, "output_tokens")?.asInt()
                    )
                )
            }
        }
    }

    private fun contentToText(node: JsonNode?): String {
        if (node == null || node.isNull) return ""
        return when {
            node.isTextual -> node.asText()
            node.isArray -> node.mapNotNull { block ->
                when {
                    block.isTextual -> block.asText()
                    block.isObject -> Nodes.text(block, "text", "content")
                    else -> null
                }
            }.joinToString("\n")
            node.isObject -> Nodes.text(node, "text", "content").orEmpty()
            else -> ""
        }
    }

    private fun extractError(payload: String): String? {
        if (payload.isBlank()) return null
        return try {
            val root = Json.parseTree(payload)
            val error = root.get("error")
            when {
                error != null && error.isTextual -> error.asText()
                error != null && error.isObject -> Nodes.text(error, "message", "msg", "type", "detail")
                else -> Nodes.text(root, "message", "detail", "msg")
            } ?: Text.plain(payload, 300).ifBlank { null }
        } catch (_: Exception) {
            Text.plain(payload, 300).ifBlank { null }
        }
    }

    private fun friendlyError(provider: ProviderConfig, status: Int, message: String): String {
        val hint = when (status) {
            401, 403 -> "Check the API key for ${provider.name} in Settings."
            404 -> "Check the base URL and model name for ${provider.name}."
            429 -> "${provider.name} rate limit reached. Wait a moment or reduce the scope."
            400 -> "The request was rejected. Check the model name and advanced provider settings."
            else -> null
        }
        val clean = Text.plain(message, 500)
        return buildString {
            append("${provider.name} error ($status)")
            if (clean.isNotBlank()) append(": ").append(clean)
            if (hint != null) append(". ").append(hint)
        }
    }

    private fun backoffMillis(attempt: Int, response: HttpResponse<String>?): Long {
        val retryAfter = response?.headers()?.firstValue("retry-after")?.orElse(null)?.toLongOrNull()
        if (retryAfter != null) return (retryAfter * 1000L).coerceIn(500L, 15_000L)
        return (1_200L * (1 shl (attempt - 1).coerceAtLeast(0))).coerceIn(500, 8_000)
    }

    private fun sleep(millis: Long, cancel: () -> Boolean) {
        var remaining = millis
        while (remaining > 0) {
            if (cancel()) throw LlmException("Scan cancelled.")
            val step = minOf(remaining, 200)
            Thread.sleep(step)
            remaining -= step
        }
    }

    companion object {
        private fun defaultHttpClient(): HttpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .proxy(proxySelector())
            .build()

        /**
         * Java's HttpClient does not read the standard http_proxy / https_proxy
         * environment variables. curl does, which is why a provider can work in
         * curl but time out inside Burp. Honour those variables explicitly.
         */
        private fun proxySelector(): ProxySelector {
            val env = System.getenv()
            val raw = env["https_proxy"] ?: env["HTTPS_PROXY"] ?: env["http_proxy"] ?: env["HTTP_PROXY"]
            val proxy = parseProxy(raw)
            return if (proxy != null) {
                object : ProxySelector() {
                    override fun select(uri: URI?): List<Proxy> = listOf(proxy)
                    override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: IOException?) = Unit
                }
            } else {
                ProxySelector.getDefault()
            }
        }

        private fun parseProxy(raw: String?): Proxy? {
            if (raw.isNullOrBlank()) return null
            var value = raw.trim()
            if (!value.startsWith("http://") && !value.startsWith("https://")) {
                value = "http://$value"
            }
            val uri = runCatching { URI(value) }.getOrNull() ?: return null
            val host = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 8080
            return Proxy(Proxy.Type.HTTP, InetSocketAddress(host, port))
        }
    }
}
