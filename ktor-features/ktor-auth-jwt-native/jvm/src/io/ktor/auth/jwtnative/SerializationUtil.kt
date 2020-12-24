/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.auth.jwtnative

import io.ktor.util.*
import io.ktor.util.date.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*

/**
 * Kotlinx.serialization support for JWT date values as GMTDate
 */
internal object GMTDateSerializer: KSerializer<GMTDate> {
    override fun deserialize(decoder: Decoder): GMTDate = GMTDate(decoder.decodeLong() * 1000)

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("GMTDate-timestamp", PrimitiveKind.LONG)

    override fun serialize(encoder: Encoder, value: GMTDate) {
        encoder.encodeLong(value.timestamp / 1000)
    }
}

/**
 * Wraps a single string element into a list, multiple values are left as-is
 */
internal object ListOrStringSerializer : JsonTransformingSerializer<List<String>>(ListSerializer(String.serializer())) {
    // If response is not an array, then it is a single object that should be wrapped into the array
    override fun transformDeserialize(element: JsonElement): JsonElement =
        if (element !is JsonArray) JsonArray(listOf(element)) else element
}

internal object Base64UrlBinary: KSerializer<ByteArray> {
    override fun deserialize(decoder: Decoder): ByteArray =
        decoder.decodeString().decodeBase64UrlBytes()

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64UrlBinary", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(value.encodeBase64Url())
}
