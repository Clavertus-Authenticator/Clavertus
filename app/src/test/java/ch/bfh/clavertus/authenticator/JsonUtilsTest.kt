package ch.bfh.clavertus.authenticator

import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Test the JsonUtils-Utility-Class
 *
 */
class JsonUtilsTest {
    @Test
    fun checkIsJsonElementSctringTrue() {
        val jsonPrimitive = JsonPrimitive("Test")
        assertTrue(JsonUtils.isJsonElementString(jsonPrimitive))
    }

    @Test
    fun checkIsJsonElementStringFalse() {
        val jsonElement: JsonElement? = null
        assertFalse(JsonUtils.isJsonElementString(jsonElement))
    }

    @Test
    fun checkGetJsonElementStringTrue() {
        val jsonPrimitive = JsonPrimitive("Test")
        assertEquals(JsonUtils.getJsonElementString(jsonPrimitive), "Test")
    }

    @Test
    fun checkGetJsonElementStringFalse() {
        val jsonElement: JsonElement? = null
        assertEquals(JsonUtils.getJsonElementString(jsonElement), "")
    }
}
