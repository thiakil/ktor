/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.auth.jwtnative

import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.http.auth.*
import io.ktor.jwt.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.util.date.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.*
import org.slf4j.*

private val JWTAuthKey: Any = "JWTNativeAuth"
private val JWTLogger: Logger = LoggerFactory.getLogger("io.ktor.auth.jwtnative")

/**
 * JWT authentication provider that will be registered with the specified [name]
 */
public class JWTNativeAuthenticationProvider internal constructor(config: Configuration) : AuthenticationProvider(config) {

    internal val authHeader: (ApplicationCall) -> HttpAuthHeader? = config.authHeader
    internal val authenticationFunction = config.authenticationFunction
    internal val challengeFunction: JWTAuthChallengeFunction = config.challenge
    internal val keyProvider: KeyProvider = config.keyProvider
    internal val realm: String = config.realm
    internal val schemes: JWTAuthSchemes = config.schemes
    internal val validatorFn: TokenValidatorFn = config.validatorFn

    public class Configuration internal constructor(name: String?) : AuthenticationProvider.Configuration(name) {

        internal var authHeader: (ApplicationCall) -> HttpAuthHeader? =
            { call -> call.request.parseAuthorizationHeaderOrNull() }

        internal var authenticationFunction: AuthenticationFunction<DecodedJWT> = { credentials ->
            JwtPrincipal(credentials.payload)
        }

        internal var challenge: JWTAuthChallengeFunction = { scheme, realm ->
            call.respond(
                UnauthorizedResponse(
                    HttpAuthHeader.Parameterized(
                        scheme,
                        mapOf(HttpAuthHeader.Parameters.Realm to realm)
                    )
                )
            )
        }

        /** Source of private key(s) to validate JWS signatures */
        internal var keyProvider: KeyProvider = { null }

        internal var schemes = JWTAuthSchemes("Bearer")

        internal var validatorFn: TokenValidatorFn = {
            throw NotImplementedError("Token verifier not configured")
        }

        /**
         * JWT realm name that will be used during auth challenge
         */
        public var realm: String = "Ktor Server"

        /**
         * Responsible for turning a validated token into a [Principal]
         */
        public fun authFunction(block: AuthenticationFunction<DecodedJWT>) {
            authenticationFunction = block
        }

        /**
         * Http auth header retrieval function. By default it parses `Authorization` header
         * content for configured auth schemes
         */
        public fun authHeader(block: (ApplicationCall) -> HttpAuthHeader?) {
            authHeader = block
        }

        /**
         * @param [defaultScheme] default scheme that will be used to challenge the client when no valid auth is provided
         * @param [additionalSchemes] additional schemes that will be accepted when validating the authentication
         */
        public fun authSchemes(defaultScheme: String = "Bearer", vararg additionalSchemes: String) {
            schemes = JWTAuthSchemes(defaultScheme, *additionalSchemes)
        }

        /**
         * Specifies what to send back if jwt authentication fails.
         */
        public fun challenge(block: JWTAuthChallengeFunction) {
            challenge = block
        }

        public fun keyProvider(block: suspend (keyId: String?) -> SigningKey?){
            keyProvider = block
        }

        /**
         * Configure token validation. Required.
         */
        public fun validator(block: TokenValidatorFn) {
            validatorFn = block
        }

        internal fun build() = JWTNativeAuthenticationProvider(this)
    }
}

/**
 * Installs JWT Native Authentication mechanism
 */
public fun Authentication.Configuration.jwtNative(
    name: String? = null,
    configure: JWTNativeAuthenticationProvider.Configuration.() -> Unit
) {
    val provider = JWTNativeAuthenticationProvider.Configuration(name).apply(configure).build()
    val realm = provider.realm
    val authenticate = provider.authenticationFunction
    val validator = provider.validatorFn
    val schemes = provider.schemes
    provider.pipeline.intercept(AuthenticationPipeline.RequestAuthentication) { context ->
        val authHeader = provider.authHeader(call)
        if (authHeader == null) {
            context.bearerChallenge(AuthenticationFailedCause.NoCredentials, realm, schemes, provider.challengeFunction)
            return@intercept
        }

        try {
            val principal = verifyAndValidate(call, validator, authHeader, schemes, authenticate, provider.keyProvider)
            if (principal != null) {
                context.principal(principal)
            } else {
                context.bearerChallenge(
                    AuthenticationFailedCause.InvalidCredentials,
                    realm,
                    schemes,
                    provider.challengeFunction
                )
            }
        } catch (cause: Throwable) {
            val message = cause.message ?: cause.javaClass.simpleName
            JWTLogger.trace("JWT verification failed: {}", message)
            context.error(JWTAuthKey, AuthenticationFailedCause.Error(message))
        }
    }
    register(provider)
}

public data class JwtPrincipal(public val claims: JWTClaimsSet, public val extraClaims: Map<String, JsonElement> = emptyMap()): Principal, JWTClaimsSet by claims {
    public constructor(payload: JWTPayload): this(payload.claimsSet, payload.unknownClaims)
}

private fun ApplicationRequest.parseAuthorizationHeaderOrNull() = try {
    parseAuthorizationHeader()
} catch (ex: IllegalArgumentException) {
    JWTLogger.trace("Illegal HTTP auth header", ex)
    null
}

internal class JWTAuthSchemes(val defaultScheme: String, vararg additionalSchemes: String) {
    val schemes = (arrayOf(defaultScheme) + additionalSchemes).toSet()
    val schemesLowerCase = schemes.map { it.toLowerCase() }.toSet()

    operator fun contains(scheme: String): Boolean = scheme.toLowerCase() in schemesLowerCase
}

public typealias JWTAuthChallengeFunction =
    suspend PipelineContext<*, ApplicationCall>.(defaultScheme: String, realm: String) -> Unit

private fun AuthenticationContext.bearerChallenge(
    cause: AuthenticationFailedCause,
    realm: String,
    schemes: JWTAuthSchemes,
    challengeFunction: JWTAuthChallengeFunction
) = challenge(JWTAuthKey, cause) {
    challengeFunction(this, schemes.defaultScheme, realm)
    if (!it.completed && call.response.status() != null) {
        it.complete()
    }
}

/**
 * Specifies what to send back if session authentication fails.
 * @throws TokenValidator.TokenValidationFailed on validation failure
 */
public typealias TokenValidatorFn = suspend TokenValidator.() -> Unit

@Suppress("MemberVisibilityCanBePrivate", "unused")
public class TokenValidator(public val token: DecodedJWT, private val keyProvider: KeyProvider){
    /**
     * Validates the token's signature.
     * @param acceptNoneAlg Whether to accept tokens with no signature and algorithm set to "none"
     */
    public suspend fun validateSignature(acceptNoneAlg: Boolean=false){
        try {
            if (!JWS.verify(token, keyProvider, acceptNoneAlg)) {
                fail("Signature failed validation")
            }
        } catch(ex: JwsException) {
            fail(ex.message, ex)
        }
    }

    /**
     * Require that [claimValue] is equal to [expected] or fail validation with
     * "[message]. Expected [expected], found [claimValue]"
     */
    public fun <T> assertClaim(claimValue: T?, expected: T?, message: String) {
        if (claimValue != expected) {
            fail("${message}. Expected '$expected', found '$claimValue'")
        }
    }

    /**
     * Ensure the token is not expired.
     * @param requireExpiry When true, a token without an expiry set is invalid.
     */
    public fun ensureNotExpired(requireExpiry: Boolean = true) {
        if (requireExpiry && token.payload.expiresAt == null) {
            fail("No expiry present")
        }
        token.payload.expiresAt?.let { exp ->
            if (GMTDate() > exp){
                fail("Token is expired")
            }
        }
    }

    public fun requireKeyId(keyId: String?) {
        assertClaim(token.header.keyId, keyId, "KeyId mismatch")
    }

    public fun requireAlgorithm(algorithm: JwsAlgorithm){
        assertClaim(token.header.algorithm, algorithm.jwaId, "Algorithm mismatch")
    }

    public fun requireIssuer(issuer: String) {
        assertClaim(token.payload.issuer, issuer, "Issuer mismatch")
    }

    public fun requireAudience(audience: String) {
        assertClaim(token.payload.audience?.contains(audience), true, "Audience mismatch")
    }
    
    public fun fail(reason: String, cause: Throwable? = null): Nothing = throw TokenValidationFailed(reason, cause)

    public class TokenValidationFailed(message: String, cause: Throwable? = null):Exception(message, cause)
}

private suspend fun verifyAndValidate(
    call: ApplicationCall,
    jwtValidatorFn: TokenValidatorFn,
    authHeader: HttpAuthHeader,
    schemes: JWTAuthSchemes,
    authFunction: AuthenticationFunction<DecodedJWT>,
    keyProvider: KeyProvider
): Principal? {
    val jwt = authHeader.getTokenFromHeader(schemes)?.let {
        try {
            JWT.decode(it)
        } catch (ex: JWSDecodeException) {
            JWTLogger.trace("Token decode failed: {}", ex.message)
            return@let null
        }
    } ?: return null

    try {
        jwtValidatorFn(TokenValidator(jwt, keyProvider))
    } catch (ex: TokenValidator.TokenValidationFailed){
        JWTLogger.trace("Token validation failed: {}", ex.message)
        return null
    }

    return authFunction(call, jwt)
}

private fun HttpAuthHeader.getTokenFromHeader(schemes: JWTAuthSchemes) = when {
    this is HttpAuthHeader.Single && authScheme in schemes -> blob
    else -> null
}
