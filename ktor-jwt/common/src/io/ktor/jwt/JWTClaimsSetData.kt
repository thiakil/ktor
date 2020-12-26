/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import io.ktor.util.date.*
import kotlinx.serialization.*

/**
 * Data class impl of [JWTClaimsSet]
 *
 * @inheritDoc
 */
@Serializable
public data class JWTClaimsSetData(

    @SerialName("iss")
    override val issuer: String? = null,

    @SerialName("sub")
    override val subject: String? = null,

    @SerialName("aud")
    @Serializable(with= ListOrStringSerializer::class)
    override val audience: List<String>? = null,

    @SerialName("exp")
    @Serializable(with = GMTDateSerializer::class)
    override val expiresAt: GMTDate? = null,

    @SerialName("nbf")
    @Serializable(with = GMTDateSerializer::class)
    override val notBefore: GMTDate? = null,

    @SerialName("iat")
    @Serializable(with = GMTDateSerializer::class)
    override val issuedAt: GMTDate? = null,

    @SerialName("jti")
    override val jwtId: String? = null,

    @SerialName("auth_time")
    @Serializable(with = GMTDateSerializer::class)
    override val authTime: GMTDate? = null,

    @SerialName("nonce")
    override val nonce: String? = null,

    @SerialName("acr")
    override val authenticationContextClassReference: String? = null,

    @SerialName("amr")
    override val authenticationMethodsReferences: List<String>? = null,

    @SerialName("azp")
    override val authorizedParty: String? = null,

    @SerialName("at_hash")
    override val accessTokenHash: String? = null,

    @SerialName("name")
    override val name: String? = null,

    @SerialName("given_name")
    override val givenName: String? = null,

    @SerialName("family_name")
    override val familyName: String? = null,

    @SerialName("middle_name")
    override val middleName: String? = null,

    @SerialName("nickname")
    override val nickname: String? = null,

    @SerialName("preferred_username")
    override val preferredUsername: String? = null,

    @SerialName("profile")
    override val profile: String? = null,

    @SerialName("picture")
    override val picture: String? = null,

    @SerialName("website")
    override val website: String? = null,

    @SerialName("email")
    override val email: String? = null,

    @SerialName("email_verified")
    override val emailVerified: Boolean? = null,

    @SerialName("gender")
    override val gender: String? = null,

    @SerialName("birthdate")
    override val birthdate: String? = null,

    @SerialName("zoneinfo")
    override val zoneinfo: String? = null,

    @SerialName("locale")
    override val locale: String? = null,

    @SerialName("phone_number")
    override val phoneNumber: String? = null,

    @SerialName("phone_number_verified")
    override val phoneNumberVerified: Boolean? = null,

    @SerialName("address")
    override val address: Address? = null,

    @SerialName("updated_at")
    @Serializable(with = GMTDateSerializer::class)
    override val updatedAt: GMTDate? = null,

    @SerialName("sid")
    override val sessionId: String? = null,
    ) : JWTClaimsSet {
    public constructor(from: JWTClaimsSet): this(
        issuer = from.issuer,
        subject = from.subject,
        audience = from.audience,
        expiresAt = from.expiresAt,
        notBefore = from.notBefore,
        issuedAt = from.issuedAt,
        jwtId = from.jwtId,
        authTime = from.authTime,
        nonce = from.nonce,
        authenticationContextClassReference = from.authenticationContextClassReference,
        authenticationMethodsReferences = from.authenticationMethodsReferences,
        authorizedParty = from.authorizedParty,
        accessTokenHash = from.accessTokenHash,
        name = from.name,
        givenName = from.givenName,
        familyName = from.familyName,
        middleName = from.middleName,
        nickname = from.nickname,
        preferredUsername = from.preferredUsername,
        profile = from.profile,
        picture = from.picture,
        website = from.website,
        email = from.email,
        emailVerified = from.emailVerified,
        gender = from.gender,
        birthdate = from.birthdate,
        zoneinfo = from.zoneinfo,
        locale = from.locale,
        phoneNumber = from.phoneNumber,
        phoneNumberVerified = from.phoneNumberVerified,
        address = from.address?.let { Address(it) },
        updatedAt = from.updatedAt,
        sessionId = from.sessionId,
    )

    @Serializable
    public data class Address(
        @SerialName("formatted")
        public override val formatted: String? = null,

        @SerialName("street_address")
        public override val streetAddress: String? = null,

        @SerialName("locality")
        public override val locality: String? = null,

        @SerialName("region")
        public override val region: String? = null,

        @SerialName("postal_code")
        public override val postalCode: String? = null,

        @SerialName("country")
        public override val country: String? = null
    ): JWTClaimsSet.Address{
        public constructor(from: JWTClaimsSet.Address): this(
            formatted = from.formatted,
            streetAddress = from.streetAddress,
            locality = from.locality,
            region = from.region,
            postalCode = from.postalCode,
            country = from.country,
        )
    }

    @OptIn(ExperimentalSerializationApi::class)
    @Serializer(forClass = JWTClaimsSetData::class)
    public object ClaimsSetSerializer

    @OptIn(ExperimentalSerializationApi::class)
    @Serializer(forClass = JWTClaimsSetData.Address::class)
    public object AddressSerializer
}
