package ch.bfh.clavertus.authenticator.utils.serialization

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.Special
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

object CBORUtils {
    enum class KeyTransformation {
        STRING_TO_INT, INT_TO_STRING, NONE
    }
    fun transformCborData(inputCborBytes: ByteArray, keyTransformation: KeyTransformation): ByteArray {
        val inputStream = ByteArrayInputStream(inputCborBytes)
        val dataItems = CborDecoder(inputStream).decode()

        if (dataItems.isNotEmpty() && dataItems[0] is co.nstant.`in`.cbor.model.Map) {
            val originalMap = dataItems[0] as co.nstant.`in`.cbor.model.Map
            val transformedMap = co.nstant.`in`.cbor.model.Map()

            originalMap.keys.forEach { key ->
                val value = originalMap[key]
                when {
                    key is UnicodeString && keyTransformation ==
                        KeyTransformation.STRING_TO_INT && key.string.toIntOrNull() != null -> {
                        // Transform the string key to an int key and handle the value accordingly
                        val intKey = UnsignedInteger(key.string.toLong())
                        transformedMap.put(intKey, transformValue(value, key, keyTransformation))
                    }
                    key is UnsignedInteger && keyTransformation == KeyTransformation.INT_TO_STRING -> {
                        // Transform the int key to a string key and handle the value accordingly
                        val stringKey = UnicodeString(key.value.toString())
                        transformedMap.put(stringKey, transformValue(value, key, keyTransformation))
                    }
                    else -> {
                        // No key transformation needed; handle the value accordingly
                        transformedMap.put(key, transformValue(value, key, keyTransformation))
                    }
                }
            }

            // Prepare for re-encoding
            val outputStream = ByteArrayOutputStream()
            CborEncoder(outputStream).encode(transformedMap)
            return outputStream.toByteArray()
        }

        // Return the original input if the first item is not a co.nstant.`in`.cbor.model.Map or no transformation was necessary
        return inputCborBytes
    }

    @Suppress("NestedBlockDepth", "CyclomaticComplexMethod", "LongMethod")
    private fun transformValue(value: DataItem?, key: DataItem?, keyTransformation: KeyTransformation): DataItem? {
        return when {
            // X5C encoding (From list of ByteArrays to list of ByteStrings)
            key is UnicodeString && key.string == "x5c" && value is co.nstant.`in`.cbor.model.Array &&
                keyTransformation == KeyTransformation.STRING_TO_INT -> {
                val newArray = co.nstant.`in`.cbor.model.Array()
                value.dataItems.forEach { item ->
                    if (item is co.nstant.`in`.cbor.model.Array) {
                        if (item != Special.BREAK) {
                            val byteList = mutableListOf<Byte>()
                            item.dataItems.forEach { innerItem ->
                                if (innerItem is UnsignedInteger) {
                                    val byte = innerItem.value.byteValueExact()
                                    byteList.add(byte)
                                }
                                if (innerItem is NegativeInteger) {
                                    val byte = innerItem.value.byteValueExact()
                                    byteList.add(byte)
                                }
                            }
                            val newByteString = ByteString(byteList.toByteArray())
                            newArray.add(transformValue(newByteString, null, keyTransformation))
                        }
                    }
                }
                newArray
            }
            // X5C decoding (From list of ByteStrings to list of ByteArrays)
            key is UnicodeString && key.string == "x5c" && value is co.nstant.`in`.cbor.model.Array &&
                keyTransformation == KeyTransformation.INT_TO_STRING -> {
                val originalArray = co.nstant.`in`.cbor.model.Array()
                value.dataItems.forEach { item ->
                    if (item is ByteString) {
                        val byteArr = item.bytes
                        val innerArray = co.nstant.`in`.cbor.model.Array()
                        byteArr.forEach { byte ->
                            val intValue = byte.toInt()
                            if (intValue >= 0) {
                                innerArray.add(UnsignedInteger(intValue.toBigInteger()))
                            } else {
                                innerArray.add(NegativeInteger(intValue.toBigInteger()))
                            }
                        }
                        originalArray.add(
                            transformValue(innerArray, null, keyTransformation)
                        )
                    }
                }
                originalArray
            }
            value is co.nstant.`in`.cbor.model.Map -> {
                // Recursively transform nested maps
                val newMap = co.nstant.`in`.cbor.model.Map()
                value.keys.forEach { nestedKey ->
                    newMap.put(nestedKey, transformValue(value[nestedKey], nestedKey, keyTransformation))
                }
                newMap
            }
            value is co.nstant.`in`.cbor.model.Array -> {
                // Recursively transform nested arrays
                val newArray = co.nstant.`in`.cbor.model.Array()
                value.dataItems.forEach { item ->
                    if (item != Special.BREAK) {
                        newArray.add(transformValue(item, null, keyTransformation))
                    }
                }
                newArray
            }
            else -> value // For other types, no transformation needed
        }
    }
}
