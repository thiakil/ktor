/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import io.ktor.util.date.*
import kotlinx.serialization.*

/**
 * Decoded claims from the base [JWT Claims](https://tools.ietf.org/html/rfc7519#section-4.1),
 * and from the [registry](https://www.iana.org/assignments/jwt/jwt.xhtml)
 *
 * Properties are null when not present in the parsed Claims Set. Consult the relevant RFC to determine token validity.
 */
public interface IJWTClaimsSet {
    /**
     * Get the value of the "iss" claim, or null if it's not available.
     *
     * The "iss" (issuer) claim identifies the principal that issued the JWT.  The processing of this claim is generally
     * application specific. The "iss" value is a case-sensitive string containing a StringOrURI value.
     */
    @SerialName("iss")
    public val issuer: String?

    /**
     * Get the value of the "sub" claim, or null if it's not available.
     *
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.  The claims in a JWT are
     * normally statements about the subject.  The subject value MUST either be scoped to be locally unique in the
     * context of the issuer or be globally unique.
     * The processing of this claim is generally application specific. The "sub" value is a case-sensitive string
     * containing a StringOrURI value.
     */
    @SerialName("sub")
    public val subject: String?

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is  intended for.  Each principal intended to
     * process the JWT MUST identify itself with a value in the audience claim.  If the principal processing the claim
     * does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-sensitive strings, each containing a
     * StringOrURI value.  In the special case when the JWT has one audience, the "aud" value MAY be a single
     * case-sensitive string containing a StringOrURI value. The interpretation of audience values is generally
     * application specific.
     */
    @SerialName("aud")
    @Serializable(with = ListOrStringSerializer::class)
    public val audience: List<String>?

    /**
     * The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted
     * for processing. The processing of the "exp" claim requires that the current date/time MUST be before the
     * expiration date/time listed in the "exp" claim. Implementers MAY provide for some small leeway, usually no more
     * than a few minutes, to account for clock skew.
     */
    @SerialName("exp")
    @Serializable(with = GMTDateSerializer::class)
    public val expiresAt: GMTDate?

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
     * The processing of the "nbf" claim requires that the current date/time MUST be after or equal to the not-before
     * date/time listed in the "nbf" claim. Implementers MAY provide for some small leeway, usually no more than a few
     * minutes, to account for clock skew.
     */
    @SerialName("nbf")
    @Serializable(with = GMTDateSerializer::class)
    public val notBefore: GMTDate?

    /**
     * The "iat" (issued at) claim identifies the time at which the JWT was issued. This claim can be used to determine
     * the age of the JWT.
     */
    @SerialName("iat")
    @Serializable(with = GMTDateSerializer::class)
    public val issuedAt: GMTDate?

    /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT. The identifier value MUST be assigned in a
     * manner that ensures that there is a negligible probability that the same value will be accidentally assigned to
     * a different data object; if the application uses multiple issuers, collisions MUST be prevented among values
     * produced by different issuers as well.  The "jti" claim can be used to prevent the JWT from being replayed.
     * The "jti" value is a case-sensitive string.
     */
    @SerialName("jti")
    public val jwtId: String?

    /**
     * OpenID Connect claim.
     *
     * Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds
     * from 1970-01-01T0:0:0Z as measured in UTC until the date/time. When a max_age request is made or when auth_time
     * is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL.
     * (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE auth_time response parameter.)
     */
    @SerialName("auth_time")
    @Serializable(with = GMTDateSerializer::class)
    public val authTime: GMTDate?

    /**
     * OpenID Connect claim.
     *
     * String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is
     * passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients
     * MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication
     * Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the
     * ID Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers
     * SHOULD perform no other processing on nonce values used. The nonce value is a case sensitive string.
     */
    @SerialName("nonce")
    public val nonce: String?

    /**
     * OpenID Connect claim.
     *
     * OPTIONAL. Authentication Context Class Reference. String specifying an Authentication Context Class Reference
     * value that identifies the Authentication Context Class that the authentication performed satisfied.
     * The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 level 1.
     * Authentication using a long-lived browser cookie, for instance, is one example where the use of "level 0" is
     * appropriate. Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary
     * value. (This corresponds to the OpenID 2.0 PAPE nist_auth_level 0.) An absolute URI or an RFC 6711 registered
     * name SHOULD be used as the acr value; registered names MUST NOT be used with a different meaning than that which
     * is registered. Parties using this claim will need to agree upon the meanings of the values used, which may be
     * context-specific. The acr value is a case sensitive string.
     */
    @SerialName("acr")
    public val authenticationContextClassReference: String?

    /**
     * OpenID Connect claim.
     *
     * OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers for authentication
     * methods used in the authentication. For instance, values might indicate that both password and OTP authentication
     * methods were used. The definition of particular values to be used in the amr Claim is beyond the scope of the
     * OpenID Connect specification. Parties using this claim will need to agree upon the meanings of the values used,
     * which may be context-specific. The amr value is an array of case sensitive strings.
     */
    @SerialName("amr")
    public val authenticationMethodsReferences: List<String>?

    /**
     * OpenID Connect claim.
     *
     * OPTIONAL. Authorized party - the party to which the ID Token was issued. If present, it MUST contain the
     * OAuth 2.0 Client ID of this party. This Claim is only needed when the ID Token has a single audience value and
     * that audience is different than the authorized party. It MAY be included even when the authorized party is the
     * same as the sole audience. The azp value is a case sensitive string containing a StringOrURI value.
     */
    @SerialName("azp")
    public val authorizedParty: String?

    /**
     * OpenID Connect claim.
     *
     * OPTIONAL. Access Token hash value. Its value is the base64url encoding of the left-most half of the hash of the
     * octets of the ASCII representation of the access_token value, where the hash algorithm used is the hash algorithm
     * used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the
     * access_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The at_hash value
     * is a case sensitive string.
     */
    @SerialName("at_hash")
    public val accessTokenHash: String?

    /**
     * OpenID Connect claim.
     *
     * End-User's full name in displayable form including all name parts, possibly including titles and suffixes,
     * ordered according to the End-User's locale and preferences.
     */
    @SerialName("name")
    public val name: String?

    /**
     * OpenID Connect claim.
     *
     * Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names;
     * all can be present, with the names being separated by space characters.
     */
    @SerialName("given_name")
    public val givenName: String?

    /**
     * OpenID Connect claim.
     *
     * Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or
     * no family name; all can be present, with the names being separated by space characters.
     */
    @SerialName("family_name")
    public val familyName: String?

    /**
     * OpenID Connect claim.
     *
     * Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be
     * present, with the names being separated by space characters.
     * Also note that in some cultures, middle names are not used.
     */
    @SerialName("middle_name")
    public val middleName: String?

    /**
     * OpenID Connect claim.
     *
     * Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of
     * Mike might be returned alongside a given_name value of Michael.
     */
    @SerialName("nickname")
    public val nickname: String?

    /**
     * OpenID Connect claim.
     *
     * Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY
     * be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this
     * value being unique, as discussed in Section 5.7.
     */
    @SerialName("preferred_username")
    public val preferredUsername: String?

    /**
     * OpenID Connect claim.
     *
     * URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
     */
    @SerialName("profile")
    public val profile: String?

    /**
     * OpenID Connect claim.
     *
     * URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF
     * image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a
     * profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary
     * photo taken by the End-User.
     */
    @SerialName("picture")
    public val picture: String?

    /**
     * OpenID Connect claim.
     *
     * URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an
     * organization that the End-User is affiliated with.
     */
    @SerialName("website")
    public val website: String?

    /**
     * OpenID Connect claim.
     *
     * End-User's preferred e-mail address. Its value MUST conform to the RFC 5322 addr-spec syntax. The RP MUST NOT
     * rely upon this value being unique, as discussed in Section 5.7.
     */
    @SerialName("email")
    public val email: String?

    /**
     * OpenID Connect claim.
     *
     * True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this
     * means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the
     * time the verification was performed. The means by which an e-mail address is verified is context-specific, and
     * dependent upon the trust framework or contractual agreements within which the parties are operating.
     */
    @SerialName("email_verified")
    public val emailVerified: Boolean?

    /**
     * OpenID Connect claim.
     *
     * End-User's gender. Values defined by this specification are female and male. Other values MAY be used when
     * neither of the defined values are applicable.
     */
    @SerialName("gender")
    public val gender: String?

    /**
     * OpenID Connect claim.
     *
     * End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000,
     * indicating that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the
     * underlying platform's date related function, providing just year can result in varying month and day, so the
     * implementers need to take this factor into account to correctly process the dates.
     */
    @SerialName("birthdate")
    public val birthdate: String?

    /**
     * OpenID Connect claim.
     *
     * String from zoneinfo time zone database representing the End-User's time zone. For example, Europe/Paris or
     * America/Los_Angeles.
     */
    @SerialName("zoneinfo")
    public val zoneinfo: String?

    /**
     * OpenID Connect claim.
     *
     * End-User's locale, represented as a BCP47 (RFC5646) language tag. This is typically an ISO 639-1 Alpha-2
     * language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example,
     * en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather
     * than a dash, for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
     */
    @SerialName("locale")
    public val locale: String?

    /**
     * OpenID Connect claim.
     *
     * End-User's preferred telephone number. E.164 is RECOMMENDED as the format of this Claim, for example,
     * +1 (425) 555-1212 or +56 (2) 687 2400.
     * If the phone number contains an extension, it is RECOMMENDED that the extension be represented using the
     * RFC 3966 extension syntax, for example, +1 (604) 555-1234;ext=5678.
     */
    @SerialName("phone_number")
    public val phoneNumber: String?

    /**
     * OpenID Connect claim.
     *
     * True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means
     * that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time
     * the verification was performed. The means by which a phone number is verified is context-specific, and dependent
     * upon the trust framework or contractual agreements within which the parties are operating. When true,
     * the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
     */
    @SerialName("phone_number_verified")
    public val phoneNumberVerified: Boolean?

    /**
     * OpenID Connect claim.
     *
     * End-User's preferred postal address. The value of the address member is a JSON structure containing some or all
     * of the members defined in OpenId Connect [Section 5.1.1](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim).
     */
    @SerialName("address")
    public val address: JWTClaimsSet.Address?

    /**
     * OpenID Connect claim.
     *
     * Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds
     * from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
     */
    @SerialName("updated_at")
    @Serializable(with = GMTDateSerializer::class)
    public val updatedAt: GMTDate?

    /**
     * OpenID Connect Front Channel Logout claim.
     *
     * String identifier for a Session. This represents a Session of a User Agent or device for a logged-in End-User at
     * an RP. Different sid values are used to identify distinct sessions at an OP. The sid value need only be unique in
     * the context of a particular issuer. Its contents are opaque to the RP. Its syntax is the same as an
     * OAuth 2.0 Client Identifier.
     */
    @SerialName("sid")
    public val sessionId: String?
}
