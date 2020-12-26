/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import io.ktor.jwt.algorithms.*
import io.ktor.util.date.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*

private val jsonFormat = Json {  }

@JwtDSL
@Serializable
public class JwtBuilder: JWTClaimsSet {
    @JwtDSL
    @SerialName("iss")
    override var issuer: String? = null

    @JwtDSL
    @SerialName("sub")
    override var subject: String? = null

    @SerialName("aud")
    @Serializable(with= ListOrStringSerializer::class)
    @JwtDSL
    override var audience: List<String>? = null

    @SerialName("exp")
    @Serializable(with = GMTDateSerializer::class)
    @JwtDSL
    override var expiresAt: GMTDate? = null

    @SerialName("nbf")
    @Serializable(with = GMTDateSerializer::class)
    @JwtDSL
    override var notBefore: GMTDate? = null

    @JwtDSL
    @SerialName("iat")
    @Serializable(with = GMTDateSerializer::class)
    override var issuedAt: GMTDate? = null

    @JwtDSL
    @SerialName("jti")
    override var jwtId: String? = null

    @JwtDSL
    @SerialName("auth_time")
    @Serializable(with = GMTDateSerializer::class)
    override var authTime: GMTDate? = null

    @JwtDSL
    @SerialName("nonce")
    override var nonce: String? = null

    @JwtDSL
    @SerialName("acr")
    override var authenticationContextClassReference: String? = null

    @JwtDSL
    @SerialName("amr")
    override var authenticationMethodsReferences: List<String>? = null

    @JwtDSL
    @SerialName("azp")
    override var authorizedParty: String? = null

    @JwtDSL
    @SerialName("at_hash")
    override var accessTokenHash: String? = null

    @JwtDSL
    @SerialName("name")
    override var name: String? = null

    @JwtDSL
    @SerialName("given_name")
    override var givenName: String? = null

    @JwtDSL
    @SerialName("family_name")
    override var familyName: String? = null

    @JwtDSL
    @SerialName("middle_name")
    override var middleName: String? = null

    @JwtDSL
    @SerialName("nickname")
    override var nickname: String? = null

    @JwtDSL
    @SerialName("preferred_username")
    override var preferredUsername: String? = null

    @JwtDSL
    @SerialName("profile")
    override var profile: String? = null

    @JwtDSL
    @SerialName("picture")
    override var picture: String? = null

    @JwtDSL
    @SerialName("website")
    override var website: String? = null

    @JwtDSL
    @SerialName("email")
    override var email: String? = null

    @JwtDSL
    @SerialName("email_verified")
    override var emailVerified: Boolean? = null

    @JwtDSL
    @SerialName("gender")
    override var gender: String? = null

    @JwtDSL
    @SerialName("birthdate")
    override var birthdate: String? = null

    @JwtDSL
    @SerialName("zoneinfo")
    override var zoneinfo: String? = null

    @JwtDSL
    @SerialName("locale")
    override var locale: String? = null

    @JwtDSL
    @SerialName("phone_number")
    override var phoneNumber: String? = null

    @JwtDSL
    @SerialName("phone_number_verified")
    override var phoneNumberVerified: Boolean? = null

    @JwtDSL
    @SerialName("address")
    override var address: Address? = null

    @JwtDSL
    @SerialName("updated_at")
    @Serializable(with = GMTDateSerializer::class)
    override var updatedAt: GMTDate? = null

    @JwtDSL
    @SerialName("sid")
    override var sessionId: String? = null

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

    @JwtDSL
    public fun address(block: Address.()->Unit) {
        this.address = Address().apply(block)
    }

    internal fun build(): JWTPayload {
        return JWTPayload(
            JWTClaimsSetData(this),
            additionalClaims
        )
    }

    @Serializable
    public class Address: JWTClaimsSet.Address {
        @JwtDSL
        @SerialName("formatted")
        public override var formatted: String? = null

        @JwtDSL
        @SerialName("street_address")
        public override val streetAddress: String? = null

        @JwtDSL
        @SerialName("locality")
        public override val locality: String? = null

        @JwtDSL
        @SerialName("region")
        public override val region: String? = null

        @JwtDSL
        @SerialName("postal_code")
        public override val postalCode: String? = null

        @JwtDSL
        @SerialName("country")
        public override val country: String? = null
    }
}

@DslMarker
internal annotation class JwtDSL

@JwtDSL
public fun makeJWT(block: JwtBuilder.()->Unit): JWTPayload = JwtBuilder().apply(block).build()

@JwtDSL
@Serializable
public class JwtSignatureBuilder(
    @Transient
    private val payload: JWTPayload = JWTPayload(JWTClaimsSetData())
): JOSEHeader {

    @JwtDSL
    @Transient
    public var key: SigningKey = NoSigningKey
        set(value) {
            field = value
            if (keyId == null && value is JsonWebKey && value.keyId != null){
                this.keyId = value.keyId
            }
        }

    @SerialName("typ")
    @JwtDSL
    public override var type: String? = null

    @SerialName("alg")
    public override val algorithm: String get() = alg.jwaId

    @JwtDSL
    @Transient
    public var alg: JwsAlgorithm = None

    @JwtDSL
    @SerialName("jku")
    public override var jwkSetUrl: String? = null

    @JwtDSL
    @SerialName("jwk")
    public override var jsonWebKey: JsonWebKey? = null
        set(value) {
            field = value
            value?.let { key = it }
        }

    @JwtDSL
    @SerialName("kid")
    public override var keyId: String? = null

    @JwtDSL
    @SerialName("x5u")
    public override var x509Url: String? = null

    @JwtDSL
    @SerialName("x5c")
    public override var x509CertChain: List<String>? = null

    @JwtDSL
    @SerialName("cty")
    public override var contentType: String? = null

    @JwtDSL
    @SerialName("crit")
    public override var critical: List<String>? = null

    @JwtDSL
    public suspend fun fromKeyProvider(keyId: String? = null, provider: KeyProvider){
        this.keyId = keyId
        this.key = provider(keyId)!!
    }

    internal fun build(): String {
        val header = JOSEHeaderData(
            type = this.type,
            algorithm = this.algorithm,
            jwkSetUrl = this.jwkSetUrl,
            jsonWebKey = this.jsonWebKey,
            keyId = this.keyId,
            x509Url = this.x509Url,
            x509CertChain = this.x509CertChain,
            contentType = this.contentType,
            critical = this.critical,
        )
        val toSign = payload.serialise(header)
        return "${toSign}." + alg.sign(toSign, key)
    }

    private object NoSigningKey: SigningKey
}

@JwtDSL
public suspend fun JWTPayload.sign(block: suspend JwtSignatureBuilder.()->Unit): String {
    val sig = JwtSignatureBuilder(this)
    sig.block()
    return sig.build()
}
