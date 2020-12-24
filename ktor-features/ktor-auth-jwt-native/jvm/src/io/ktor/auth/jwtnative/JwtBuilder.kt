/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.auth.jwtnative

import io.ktor.util.date.*
import kotlinx.serialization.json.*

private val jsonFormat = Json {  }

@JwtDSL
public class JwtBuilder: IJWTClaimsSet {
    @JwtDSL override var issuer: String? = null
    @JwtDSL override var subject: String? = null
    @JwtDSL override var audience: List<String>? = null
    @JwtDSL override var expiresAt: GMTDate? = null
    @JwtDSL override var notBefore: GMTDate? = null
    @JwtDSL override var issuedAt: GMTDate? = null
    @JwtDSL override var jwtId: String? = null
    @JwtDSL override var authTime: GMTDate? = null
    @JwtDSL override var nonce: String? = null
    @JwtDSL override var authenticationContextClassReference: String? = null
    @JwtDSL override var authenticationMethodsReferences: List<String>? = null
    @JwtDSL override var authorizedParty: String? = null
    @JwtDSL override var accessTokenHash: String? = null
    @JwtDSL override var name: String? = null
    @JwtDSL override var givenName: String? = null
    @JwtDSL override var familyName: String? = null
    @JwtDSL override var middleName: String? = null
    @JwtDSL override var nickname: String? = null
    @JwtDSL override var preferredUsername: String? = null
    @JwtDSL override var profile: String? = null
    @JwtDSL override var picture: String? = null
    @JwtDSL override var website: String? = null
    @JwtDSL override var email: String? = null
    @JwtDSL override var emailVerified: Boolean? = null
    @JwtDSL override var gender: String? = null
    @JwtDSL override var birthdate: String? = null
    @JwtDSL override var zoneinfo: String? = null
    @JwtDSL override var locale: String? = null
    @JwtDSL override var phoneNumber: String? = null
    @JwtDSL override var phoneNumberVerified: Boolean? = null
    @JwtDSL override var address: JWTClaimsSet.Address? = null
    @JwtDSL override var updatedAt: GMTDate? = null
    @JwtDSL override var sessionId: String? = null

    private val additionalClaims: MutableMap<String, JsonElement> = mutableMapOf()

    @JwtDSL
    public operator fun plus(customClaim: Pair<String, Any>) {
        additionalClaims[customClaim.first] = when (val value = customClaim.second) {
            is JsonElement -> value
            else -> jsonFormat.encodeToJsonElement(value)
        }
    }

    @JwtDSL
    public var singleAudience: String?
        get() = this.audience?.joinToString()
        set(value) {
            this.audience = when(value){
                null -> null
                else -> listOf(value)
            }
        }

    internal fun build(): JWTPayload {
        return JWTPayload(
            JWTClaimsSet(
                issuer = issuer,
                subject = subject,
                audience = audience,
                expiresAt = expiresAt,
                notBefore = notBefore,
                issuedAt = issuedAt,
                jwtId = jwtId,
                authTime = authTime,
                nonce = nonce,
                authenticationContextClassReference = authenticationContextClassReference,
                authenticationMethodsReferences = authenticationMethodsReferences,
                authorizedParty = authorizedParty,
                accessTokenHash = accessTokenHash,
                name = name,
                givenName = givenName,
                familyName = familyName,
                middleName = middleName,
                nickname = nickname,
                preferredUsername = preferredUsername,
                profile = profile,
                picture = picture,
                website = website,
                email = email,
                emailVerified = emailVerified,
                gender = gender,
                birthdate = birthdate,
                zoneinfo = zoneinfo,
                locale = locale,
                phoneNumber = phoneNumber,
                phoneNumberVerified = phoneNumberVerified,
                address = address,
                updatedAt = updatedAt,
                sessionId = sessionId
            ),
            additionalClaims
        )
    }
}

@DslMarker
internal annotation class JwtDSL

@JwtDSL
public fun makeJWT(block: JwtBuilder.()->Unit): JWTPayload = JwtBuilder().apply(block).build()
