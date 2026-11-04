package io.sectiv.burp.core

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import java.util.UUID

/** Severity used across the dashboard, reports and AI prompts. */
enum class Severity(val label: String, val rank: Int) {
    CRITICAL("Critical", 0),
    HIGH("High", 1),
    MEDIUM("Medium", 2),
    LOW("Low", 3),
    INFO("Info", 4);

    companion object {
        fun from(value: String?): Severity? {
            val v = value?.trim()?.lowercase() ?: return null
            return when (v) {
                "critical", "crit", "severe", "blocker" -> CRITICAL
                "high", "important", "major" -> HIGH
                "medium", "moderate", "med" -> MEDIUM
                "low", "minor" -> LOW
                "info", "informational", "information", "note" -> INFO
                else -> null
            }
        }
    }
}

enum class Confidence(val label: String, val rank: Int) {
    CERTAIN("Certain", 0),
    FIRM("Firm", 1),
    TENTATIVE("Tentative", 2);

    companion object {
        fun from(value: String?): Confidence {
            return when (value?.trim()?.lowercase()) {
                "certain", "confirmed", "high", "definite" -> CERTAIN
                "firm", "likely", "medium", "probable" -> FIRM
                else -> TENTATIVE
            }
        }
    }
}

enum class FindingStatus(val label: String) {
    OPEN("Open"),
    TRIAGED("Triaged"),
    FALSE_POSITIVE("False positive"),
    RESOLVED("Resolved");

    companion object {
        fun from(value: String?): FindingStatus =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: OPEN
    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
data class Finding(
    val id: String = UUID.randomUUID().toString(),
    val fingerprint: String = "",
    val title: String = "",
    val severity: Severity = Severity.INFO,
    val confidence: Confidence = Confidence.TENTATIVE,
    val url: String = "",
    val method: String = "",
    val host: String = "",
    val port: Int = 443,
    val secure: Boolean = true,
    val description: String = "",
    val stepsToReproduce: String = "",
    val impact: String = "",
    val poc: String = "",
    val pocType: String = "",
    val evidence: String = "",
    val remediation: String = "",
    val cwe: String = "",
    val cve: String = "",
    val cvss: Double? = null,
    val skillId: String = "",
    val skillName: String = "",
    val source: String = "ai",
    val status: FindingStatus = FindingStatus.OPEN,
    val createdAt: Long = System.currentTimeMillis(),
    val requestRaw: String = "",
    val responseRaw: String = ""
) {
    val hostLabel: String
        get() = host.ifBlank {
            runCatching { java.net.URI(url).host }.getOrNull().orEmpty()
        }
}

@JsonIgnoreProperties(ignoreUnknown = true)
data class Skill(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "New skill",
    val category: String = "General",
    val description: String = "",
    val instructions: String = "",
    val enabled: Boolean = true,
    val builtIn: Boolean = false,
    val createdAt: Long = System.currentTimeMillis()
)

/** Wire protocol used by a provider. */
enum class ProviderKind {
    OPENAI,
    ANTHROPIC
}

@JsonIgnoreProperties(ignoreUnknown = true)
data class ProviderConfig(
    val id: String,
    val name: String,
    val kind: ProviderKind = ProviderKind.OPENAI,
    val baseUrl: String = "",
    val model: String = "",
    val apiKey: String = "",
    val maxTokens: Int = 8192,
    val maxTokensField: String = "max_tokens",
    val temperature: Double? = 0.1,
    val timeoutSeconds: Int = 180,
    val requiresApiKey: Boolean = true,
    val docsUrl: String = "",
    val extraHeaders: Map<String, String> = emptyMap(),
    val extraBodyJson: String = ""
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class Settings(
    val activeProviderId: String = "deepseek",
    val providers: List<ProviderConfig> = defaultProviders(),
    val chunkChars: Int = 42000,
    val maxFindingsPerChunk: Int = 8,
    val maxResponseChars: Int = 7000,
    val maskSecrets: Boolean = true,
    val allowStateChangingChecks: Boolean = false,
    val maxSwapRequests: Int = 20,
    val requestDelayMs: Int = 300,
    val autoSelectInScope: Boolean = false
) {
    fun activeProvider(): ProviderConfig =
        providers.firstOrNull { it.id == activeProviderId } ?: providers.first()

    fun provider(id: String): ProviderConfig? = providers.firstOrNull { it.id == id }

    /** Adds any presets introduced by a newer version without touching user values. */
    fun withMissingPresets(): Settings {
        val existing = providers.map { it.id }.toSet()
        val defaults = defaultProviders()
        // The original default output limit (8192) is too small now that findings
        // carry steps, impact and a PoC. Upgrade preset providers still on the old
        // default; user-tweaked values are left untouched.
        val merged = providers.map { provider ->
            val preset = defaults.firstOrNull { it.id == provider.id }
            if (preset != null && provider.maxTokens == 8192) {
                provider.copy(maxTokens = preset.maxTokens)
            } else {
                provider
            }
        } + defaults.filter { it.id !in existing }
        return copy(providers = merged)
    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
data class SectivState(
    val schemaVersion: Int = 1,
    val settings: Settings = Settings(),
    val skills: List<Skill> = defaultSkills(),
    val findings: List<Finding> = emptyList(),
    val authContext: String = ""
) {
    fun normalized(): SectivState {
        var s = settings.withMissingPresets()
        if (s.providers.none { it.id == s.activeProviderId }) {
            s = s.copy(activeProviderId = s.providers.first().id)
        }
        val skillIds = skills.map { it.id }.toSet()
        val fixedFindings = findings.map { f ->
            if (f.skillId.isNotBlank() && f.skillId !in skillIds) {
                f.copy(skillName = f.skillName.ifBlank { "Deleted skill" })
            } else f
        }
        // Migration: the original XSS skill was too strict and missed reflected XSS.
        // Upgrade it once if the stored copy still matches the old built-in text.
        val fixedSkills = skills.map { skill ->
            if (skill.builtIn && skill.id == "skill-xss" &&
                skill.instructions.contains("Do not report a finding without a demonstrated reflection")
            ) {
                defaultSkills().first { it.id == "skill-xss" }
            } else {
                skill
            }
        }
        return copy(settings = s, skills = fixedSkills, findings = fixedFindings)
    }
}

/**
 * A plain, Montoya-free snapshot of one request/response pair. Keeping this
 * separate from the Burp API makes the analysis engine testable off-target.
 */
data class CapturedExchange(
    val id: String,
    val source: String,
    val method: String,
    val url: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val path: String,
    val status: Int,
    val mime: String,
    val requestRaw: String,
    val responseRaw: String,
    val timestamp: Long = System.currentTimeMillis(),
    val hits: Int = 1
) {
    val displayPath: String
        get() = path.ifBlank { "/" }

    val length: Int
        get() = responseRaw.length
}

fun defaultProviders(): List<ProviderConfig> = listOf(
    ProviderConfig(
        id = "deepseek",
        name = "DeepSeek",
        baseUrl = "https://api.deepseek.com/v1/chat/completions",
        model = "deepseek-chat",
        maxTokens = 16384,
        temperature = 0.1,
        docsUrl = "https://platform.deepseek.com/api_keys"
    ),
    ProviderConfig(
        id = "anthropic",
        name = "Claude (Anthropic)",
        kind = ProviderKind.ANTHROPIC,
        baseUrl = "https://api.anthropic.com/v1/messages",
        model = "claude-sonnet-4-5",
        maxTokens = 16384,
        maxTokensField = "max_tokens",
        temperature = 0.1,
        docsUrl = "https://console.anthropic.com/settings/keys"
    ),
    ProviderConfig(
        id = "openai",
        name = "OpenAI",
        baseUrl = "https://api.openai.com/v1/chat/completions",
        model = "gpt-5.1",
        maxTokens = 16384,
        maxTokensField = "max_completion_tokens",
        temperature = null,
        docsUrl = "https://platform.openai.com/api-keys"
    ),
    ProviderConfig(
        id = "glm",
        name = "GLM (Zhipu)",
        baseUrl = "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        model = "glm-4.6",
        maxTokens = 16384,
        temperature = 0.1,
        docsUrl = "https://open.bigmodel.cn/usercenter/apikeys"
    ),
    ProviderConfig(
        id = "zai",
        name = "z.ai",
        baseUrl = "https://api.z.ai/api/paas/v4/chat/completions",
        model = "glm-4.6",
        maxTokens = 16384,
        temperature = 0.1,
        docsUrl = "https://z.ai/manage-apikey/apikey-list"
    ),
    ProviderConfig(
        id = "openrouter",
        name = "OpenRouter",
        baseUrl = "https://openrouter.ai/api/v1/chat/completions",
        model = "anthropic/claude-sonnet-4.5",
        maxTokens = 16384,
        temperature = 0.1,
        docsUrl = "https://openrouter.ai/settings/keys",
        extraHeaders = mapOf(
            "HTTP-Referer" to "https://github.com/sectiv",
            "X-Title" to "Sectiv"
        )
    ),
    ProviderConfig(
        id = "ollama",
        name = "Ollama (local)",
        baseUrl = "http://127.0.0.1:11434/v1/chat/completions",
        model = "llama3.1",
        maxTokens = 16384,
        temperature = 0.1,
        requiresApiKey = false,
        docsUrl = "https://ollama.com"
    ),
    ProviderConfig(
        id = "custom",
        name = "Custom (OpenAI-compatible)",
        baseUrl = "",
        model = "",
        requiresApiKey = true
    )
)
