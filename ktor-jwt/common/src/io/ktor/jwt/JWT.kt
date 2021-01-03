/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import io.ktor.util.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.*

public object JWT {
    private val base64UrlFormat: Regex = Regex("[-A-Za-z0-9_]+")
    private val serialModule: SerializersModule = SerializersModule {
        //declare the interfaces as being defaulted to the data classes
        polymorphic(JWTClaimsSet::class) {
            subclass(JWTClaimsSetData::class)
            subclass(JwtBuilder::class)
            default { JWTClaimsSetData.serializer() }
        }
        polymorphic(JWTClaimsSet.Address::class){
            subclass(JWTClaimsSetData.Address::class)
            subclass(JwtBuilder.Address::class)
            default { JWTClaimsSetData.Address.serializer() }
        }
        polymorphic(JOSEHeader::class) {
            subclass(JOSEHeaderData::class)
            subclass(JwtSignatureBuilder::class)
            default { JOSEHeaderData.serializer() }
        }
    }
    internal val json: Json = Json {
        ignoreUnknownKeys = true
        serializersModule = serialModule
    }


    @OptIn(ExperimentalSerializationApi::class)
    private val knownClaims:Set<String> = mutableSetOf<String>().also {
        val claimsSerialiser = JWTClaimsSetData.serializer()
        val numElements = claimsSerialiser.descriptor.elementsCount
        for (i in 0 until numElements) {
            it.add(claimsSerialiser.descriptor.getElementName(i))
        }
    }

    /**
     * Decode a JWS Compact Format encoded JWT
     *
     * @throws JWSDecodeException
     */
    public fun decode(jwsToken: String): DecodedJWT {
        val parts = jwsToken.split(".")
        when {
            parts.size < 2 -> throw JWSDecodeException("Invalid JWS")
            parts.size == 5 -> throw JWSDecodeException("JWE not supported")
            parts.size > 3 -> throw JWSDecodeException("Unrecognised JWS token")
            parts.size == 3 -> if (parts[2] != "" && !parts[2].matches(base64UrlFormat)) throw JWSDecodeException("Signature bas64 invalid")
        }
        if (!parts[0].matches(base64UrlFormat)) throw JWSDecodeException("Header base64 invalid")
        if (!parts[1].matches(base64UrlFormat)) throw JWSDecodeException("Payload bas64 invalid")
        val header = try {
            json.decodeFromString<JOSEHeaderData>(parts[0].decodeBase64UrlString())
        } catch (e: Exception) {
            throw JWSDecodeException("Header deserialisation failed: ${e.message}", e)
        }
        if (header.algorithm != "none" && parts.size != 3) throw JWSDecodeException("missing signature")
        val payloadRaw = json.parseToJsonElement(parts[1].decodeBase64UrlString())
        val payload = json.decodeFromJsonElement<JWTClaimsSetData>(payloadRaw)
        val payloadUnknowns = payloadRaw.jsonObject.toMutableMap()
        knownClaims.forEach { payloadUnknowns.remove(it) }
        val signature = if (parts.size == 3 && parts[2] != "") parts[2].decodeBase64UrlBytes() else null
        return DecodedJWT(
            header = header,
            payload = JWTPayload(payload, payloadUnknowns),
            signature = signature?.let { UnverifiedSignature(parts[0]+"."+parts[1], it) }
        )
    }
}

public class JWSDecodeException(message: String, cause: Exception? = null): RuntimeException(message, cause)

public data class DecodedJWT(public val header: JOSEHeader, public val payload: JWTPayload, public val signature: UnverifiedSignature?)

public data class JWTPayload(
    public val claimsSet: JWTClaimsSet,
    public val unknownClaims: Map<String, JsonElement> = emptyMap()
) : JWTClaimsSet by claimsSet {

    public fun serialise(
        header: JOSEHeader
    ): String {
        val fields = mutableMapOf<String,JsonElement>()
        fields.putAll(JWT.json.encodeToJsonElement(this.claimsSet).jsonObject)
        fields.putAll(JWT.json.encodeToJsonElement(this.unknownClaims).jsonObject)
        val payloadJson = JWT.json.encodeToString(JsonObject(fields))
        return (JWT.json.encodeToString(header).encodeBase64Url())+ "." + (payloadJson.encodeBase64Url())
    }
}

public data class UnverifiedSignature(public val subject: String, public val signature: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnverifiedSignature) return false

        if (subject != other.subject) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = subject.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}
