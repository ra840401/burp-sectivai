package io.sectiv.burp.scan

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import io.sectiv.burp.core.CapturedExchange
import java.time.ZonedDateTime

enum class HistorySource(val label: String) {
    PROXY("Proxy history"),
    SITEMAP("Site map");

    companion object {
        fun from(value: String?): HistorySource =
            entries.firstOrNull { it.label == value } ?: PROXY
    }
}

data class HistoryCollection(
    val exchanges: List<CapturedExchange>,
    val totalAvailable: Int,
    val truncated: Boolean
)

/**
 * Copies Burp's proxy/sitemap history into plain snapshots on a worker
 * thread. Raw messages are capped so a long engagement cannot exhaust memory.
 */
class HistoryCollector(private val api: MontoyaApi) {

    fun collect(source: HistorySource, limit: Int = 2500): HistoryCollection {
        return when (source) {
            HistorySource.PROXY -> collectProxy(limit)
            HistorySource.SITEMAP -> collectSitemap(limit)
        }
    }

    private fun collectProxy(limit: Int): HistoryCollection {
        val history = api.proxy().history().filter { it.hasResponse() }
        val selected = history.takeLast(limit)
        val exchanges = selected.mapNotNull { entry ->
            runCatching {
                val request = entry.request()
                val response = entry.response() ?: return@runCatching null
                val service = request.httpService()
                CapturedExchange(
                    id = "proxy:${entry.id()}",
                    source = HistorySource.PROXY.label,
                    method = request.method(),
                    url = request.url(),
                    host = service.host(),
                    port = service.port(),
                    secure = service.secure(),
                    path = request.path(),
                    status = response.statusCode().toInt(),
                    mime = runCatching { response.mimeType().name }.getOrDefault(""),
                    requestRaw = clip(request.toString(), RAW_LIMIT),
                    responseRaw = clip(response.toString(), RESPONSE_LIMIT),
                    timestamp = runCatching { entry.time().toInstant().toEpochMilli() }
                        .getOrElse { System.currentTimeMillis() }
                )
            }.getOrNull()
        }
        return HistoryCollection(exchanges, history.size, history.size > limit)
    }

    private fun collectSitemap(limit: Int): HistoryCollection {
        val all = api.siteMap().requestResponses().filter { it.hasResponse() }
        val selected = all.takeLast(limit)
        val exchanges = selected.mapIndexedNotNull { index, entry ->
            runCatching { toExchange(entry, index) }.getOrNull()
        }
        return HistoryCollection(exchanges, all.size, all.size > limit)
    }

    private fun toExchange(entry: HttpRequestResponse, index: Int): CapturedExchange? {
        val request = entry.request() ?: return null
        val response = entry.response() ?: return null
        val service = request.httpService() ?: return null
        return CapturedExchange(
            id = "sitemap:$index:${request.url()}",
            source = HistorySource.SITEMAP.label,
            method = request.method(),
            url = request.url(),
            host = service.host(),
            port = service.port(),
            secure = service.secure(),
            path = request.path(),
            status = response.statusCode().toInt(),
            mime = runCatching { response.mimeType().name }.getOrDefault(""),
            requestRaw = clip(request.toString(), RAW_LIMIT),
            responseRaw = clip(response.toString(), RESPONSE_LIMIT),
            timestamp = System.currentTimeMillis()
        )
    }

    private fun clip(text: String, max: Int): String =
        if (text.length <= max) text else text.take(max) + "\n...[truncated ${text.length - max} chars]"

    companion object {
        private const val RAW_LIMIT = 30_000
        private const val RESPONSE_LIMIT = 40_000
    }
}
