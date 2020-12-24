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

public data class JwtPrincipal(public val claims: IJWTClaimsSet, public val extraClaims: Map<String, JsonElement> = emptyMap()): Principal, IJWTClaimsSet by claims {
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

public class TokenValidator(public val token: DecodedJWT, private val keyProvider: KeyProvider){
    public suspend fun validateSignature(acceptNoneAlg: Boolean=false){
        try {
            if (!JWS.verify(token, keyProvider, acceptNoneAlg)) {
                throw TokenValidationFailed("Signature failed validation")
            }
        } catch(ex: JwsException) {
            throw TokenValidationFailed(ex.message, ex)
        }
    }

    public fun requireKeyId(keyId: String?) {
        if (token.header.keyId != keyId) {
            throw TokenValidationFailed("KeyId mismatch")
        }
    }

    public fun requireAlgorithm(algorithm: JwsAlgorithm){
        if (token.header.algorithm != algorithm.jwaId){
            throw TokenValidationFailed("Algorithm mismatch")
        }
    }

    public fun requireIssuer(issuer: String) {
        if (token.payload.issuer != issuer){
            throw TokenValidationFailed("Issuer mismatch")
        }
    }

    public fun requireAudience(audience: String) {
        if (token.payload.audience?.contains(audience) != true){
            throw TokenValidationFailed("Audience mismatch")
        }
    }

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
