package io.sectiv.burp.core

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.json.JsonReadFeature
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule

/** Shared, thread-safe Jackson setup. */
object Json {
    val mapper: ObjectMapper = JsonMapper.builder(
        JsonFactory.builder()
            .enable(JsonReadFeature.ALLOW_TRAILING_COMMA)
            .enable(JsonReadFeature.ALLOW_SINGLE_QUOTES)
            .enable(JsonReadFeature.ALLOW_UNQUOTED_FIELD_NAMES)
            .build()
    )
        .addModule(KotlinModule.Builder().build())
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        .configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS, true)
        .build()

    fun write(value: Any?): String = mapper.writeValueAsString(value)

    fun writePretty(value: Any?): String =
        mapper.writerWithDefaultPrettyPrinter().writeValueAsString(value)

    fun readState(json: String): SectivState = mapper.readValue(json, SectivState::class.java)

    fun parseTree(json: String): JsonNode = mapper.readTree(json)

    fun escapeHtml(value: String): String = buildString(value.length + 16) {
        for (c in value) {
            when (c) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                '\'' -> append("&#39;")
                else -> append(c)
            }
        }
    }
}

/** Jackson helpers that tolerate the many shapes LLMs use for the same field. */
object Nodes {
    fun field(node: JsonNode?, vararg names: String): JsonNode? {
        if (node == null || !node.isObject) return null
        for (name in names) {
            val direct = node.get(name)
            if (direct != null && !direct.isNull) return direct
        }
        val wanted = names.map { it.lowercase().replace("_", "").replace("-", "") }.toSet()
        val fields = node.fields()
        while (fields.hasNext()) {
            val (key, value) = fields.next()
            val normalized = key.lowercase().replace("_", "").replace("-", "")
            if (normalized in wanted && !value.isNull) return value
        }
        return null
    }

    fun text(node: JsonNode?, vararg names: String): String? {
        val value = field(node, *names) ?: return null
        return when {
            value.isTextual -> value.asText()
            value.isNumber || value.isBoolean -> value.asText()
            value.isArray -> value.joinToString("\n") { it.asText("") }.trim()
            value.isObject -> value.toString()
            else -> null
        }?.trim()?.takeIf { it.isNotEmpty() }
    }

    fun double(node: JsonNode?, vararg names: String): Double? {
        val value = field(node, *names) ?: return null
        return when {
            value.isNumber -> value.asDouble()
            value.isTextual -> value.asText().trim().toDoubleOrNull()
            else -> null
        }
    }
}
