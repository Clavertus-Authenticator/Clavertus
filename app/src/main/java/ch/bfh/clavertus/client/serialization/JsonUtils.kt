package ch.bfh.clavertus.client.serialization

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

object JsonUtils {
    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun isJsonElementString(jsonElement: JsonElement?): Boolean {
        return jsonElement != null && jsonElement is JsonPrimitive && jsonElement.isString
    }

    fun getJsonElementString(jsonElement: JsonElement?): String {
        return if (isJsonElementString(jsonElement)) jsonElement?.jsonPrimitive?.content.orEmpty() else ""
    }
}
