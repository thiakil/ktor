/*
 * Copyright 2014-2019 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.util

import io.ktor.utils.io.charsets.*
import io.ktor.utils.io.core.*
import kotlin.experimental.*
import kotlin.jvm.*
import kotlin.native.concurrent.*

private const val BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
private const val BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
private const val BASE64_MASK: Byte = 0x3f
private const val BASE64_PAD = '='

@SharedImmutable
private val BASE64_INVERSE_ALPHABET = IntArray(256) {
    BASE64_ALPHABET.indexOf(it.toChar())
}
@SharedImmutable
private val BASE64URL_INVERSE_ALPHABET = IntArray(256) {
    BASE64URL_ALPHABET.indexOf(it.toChar())
}

@InternalAPI
public enum class Base64Variant {
    /** Conventional Base64, the default */
    STANDARD,
    /** Base64URL, where + and / are substituted and no padding characters are required */
    URL
}

/**
 * Encode [String] in base64 format and UTF-8 character encoding.
 */
@InternalAPI
public fun String.encodeBase64(): String = buildPacket {
    writeText(this@encodeBase64)
}.encodeBase64(Base64Variant.STANDARD)

/**
 * Encode [String] in base64URL format and UTF-8 character encoding.
 */
@InternalAPI
public fun String.encodeBase64Url(): String = buildPacket {
    writeText(this@encodeBase64Url)
}.encodeBase64(Base64Variant.URL)

/**
 * Encode [ByteArray] in base64 format
 */
@InternalAPI
public fun ByteArray.encodeBase64(): String = buildPacket {
    writeFully(this@encodeBase64)
}.encodeBase64(Base64Variant.STANDARD)

/**
 * Encode [ByteArray] in base64URL format
 */
@InternalAPI
public fun ByteArray.encodeBase64Url(): String = buildPacket {
    writeFully(this@encodeBase64Url)
}.encodeBase64(Base64Variant.URL)

/**
 * Encode [ByteReadPacket] in base64 format
 */
@InternalAPI
@JvmOverloads//binary compat
public fun ByteReadPacket.encodeBase64(variant: Base64Variant = Base64Variant.STANDARD): String = buildString {
    val data = ByteArray(3)
    while (remaining > 0) {
        val read = readAvailable(data)
        data.clearFrom(read)

        val padSize = (data.size - read) * 8 / 6
        val chunk = ((data[0].toInt() and 0xFF) shl 16) or
            ((data[1].toInt() and 0xFF) shl 8) or
            (data[2].toInt() and 0xFF)

        for (index in data.size downTo padSize) {
            val char = (chunk shr (6 * index)) and BASE64_MASK.toInt()
            append(char.toBase64(variant))
        }

        if (variant != Base64Variant.URL) {
            repeat(padSize) { append(BASE64_PAD) }
        }
    }
}

/**
 * Decode [String] from base64 format encoded in UTF-8.
 */
@InternalAPI
@JvmOverloads//binary compat
public fun String.decodeBase64String(variant: Base64Variant = Base64Variant.STANDARD): String = String(decodeBase64Bytes(variant), charset = Charsets.UTF_8)

/**
 * Decode UTF-8 encoded [String] from base64URL format.
 */
@InternalAPI
public fun String.decodeBase64UrlString(): String = String(decodeBase64Bytes(Base64Variant.URL), charset = Charsets.UTF_8)


/**
 * Decode [ByteArray] from base64 format
 */
@InternalAPI
@JvmOverloads//binary compat
public fun String.decodeBase64Bytes(variant: Base64Variant = Base64Variant.STANDARD): ByteArray = buildPacket {
    writeText(dropLastWhile { it == BASE64_PAD })
}.decodeBase64Bytes(variant).readBytes()

/**
 * Decode [ByteArray] from base64URL format
 */
@InternalAPI
public fun String.decodeBase64UrlBytes(): ByteArray = decodeBase64Bytes(Base64Variant.URL)

/**
 * Decode [ByteReadPacket] from base64 format
 */
@InternalAPI
@JvmOverloads//binary compat
public fun ByteReadPacket.decodeBase64Bytes(variant: Base64Variant = Base64Variant.STANDARD): Input = buildPacket {
    val data = ByteArray(4)

    while (remaining > 0) {
        val read = readAvailable(data)

        val chunk = data.foldIndexed(0) { index, result, current ->
            result or (current.fromBase64(variant).toInt() shl ((3 - index) * 6))
        }

        for (index in data.size - 2 downTo (data.size - read)) {
            val origin = (chunk shr (8 * index)) and 0xff
            writeByte(origin.toByte())
        }
    }
}

@Suppress("unused", "KDocMissingDocumentation")
@Deprecated("Binary compatibility.", level = DeprecationLevel.HIDDEN)
public fun String.decodeBase64(): String = decodeBase64String()

@Suppress("unused", "KDocMissingDocumentation")
@Deprecated("Binary compatibility.", level = DeprecationLevel.HIDDEN)
public fun ByteReadPacket.decodeBase64(): String = decodeBase64Bytes().readText()

internal fun ByteArray.clearFrom(from: Int) {
    (from until size).forEach { this[it] = 0 }
}

internal fun Int.toBase64(variant: Base64Variant): Char = when(variant){
    Base64Variant.STANDARD -> BASE64_ALPHABET[this]
    Base64Variant.URL -> BASE64URL_ALPHABET[this]
}
internal fun Byte.fromBase64(variant: Base64Variant): Byte = when (variant){
    Base64Variant.STANDARD -> BASE64_INVERSE_ALPHABET
    Base64Variant.URL -> BASE64URL_INVERSE_ALPHABET
}[toInt() and 0xff].toByte() and BASE64_MASK

