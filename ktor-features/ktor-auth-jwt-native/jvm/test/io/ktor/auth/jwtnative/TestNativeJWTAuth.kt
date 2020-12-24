/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.auth.jwtnative

import com.nhaarman.mockito_kotlin.*
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.auth.Principal
import io.ktor.jwt.algorithms.*
import io.ktor.http.*
import io.ktor.http.auth.*
import io.ktor.jwt.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.*
import java.security.*
import java.security.interfaces.*
import java.util.concurrent.*
import kotlin.test.*

class JWTAuthTest {

    @Test
    fun testJwtNoAuth() {
        withApplication {
            application.configureServerJwtNative()

            val response = handleRequest {
                uri = "/"
            }

            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwtNoAuthCustomChallengeNoToken() {
        withApplication {
            application.configureServerJwtNative {
                challenge { _, _ ->
                    call.respond(UnauthorizedResponse(HttpAuthHeader.basicAuthChallenge("custom1", Charsets.UTF_8)))
                }
            }

            val response = handleRequest {
                uri = "/"
            }

            verifyResponseUnauthorized(response)
            assertEquals("Basic realm=custom1, charset=UTF-8", response.response.headers[HttpHeaders.WWWAuthenticate])
        }
    }

    @Test
    fun testJwtMultipleNoAuthCustomChallengeNoToken() {
        withApplication {
            application.configureServerJwtNative {
                challenge { _, _ ->
                    call.respond(UnauthorizedResponse(HttpAuthHeader.basicAuthChallenge("custom1", Charsets.UTF_8)))
                }
            }

            val response = handleRequest {
                uri = "/"
            }

            verifyResponseUnauthorized(response)
            assertEquals("Basic realm=custom1, charset=UTF-8", response.response.headers[HttpHeaders.WWWAuthenticate])
        }
    }

    @Test
    fun testJwtWithMultipleConfigurations() {
        val validated = mutableSetOf<String>()
        var currentPrincipal: (DecodedJWT) -> Principal? = { null }

        withApplication {
            application.install(Authentication) {
                val jwtVerifier = makeJwtVerifier()
                jwtNative(name = "first") {
                    realm = "realm1"
                    validator { validated.add("1"); jwtVerifier() }
                    authFunction { currentPrincipal(it) }
                    challenge { _, _ ->
                        call.respond(UnauthorizedResponse(HttpAuthHeader.basicAuthChallenge("custom1", Charsets.UTF_8)))
                    }
                    keyProvider = getJwkProviderMock()
                }
                jwtNative(name = "second") {
                    realm = "realm2"
                    validator { validated.add("2"); jwtVerifier() }
                    authFunction { currentPrincipal(it) }
                    challenge { _, _ ->
                        call.respond(UnauthorizedResponse(HttpAuthHeader.basicAuthChallenge("custom2", Charsets.UTF_8)))
                    }
                    keyProvider = getJwkProviderMock()
                }
            }

            application.routing {
                authenticate("first", "second") {
                    get("/") {
                        val principal = call.authentication.principal<JwtPrincipal>()!!
                        call.respondText("Secret info, ${principal.audience}")
                    }
                }
            }

            val token = getToken()
            handleRequestWithToken(token).let { call ->
                verifyResponseUnauthorized(call)
                assertEquals(
                    "Basic realm=custom1, charset=UTF-8",
                    call.response.headers[HttpHeaders.WWWAuthenticate]
                )
            }
            assertEquals(setOf("1", "2"), validated)

            currentPrincipal = { JwtPrincipal(it.payload) }
            validated.clear()

            handleRequestWithToken(token).let { call ->
                assertEquals(HttpStatusCode.OK, call.response.status())

                assertEquals(
                    "Secret info, [$audience]",
                    call.response.content
                )

                assertNull(call.response.headers[HttpHeaders.WWWAuthenticate])
            }

            assertEquals(setOf("1"), validated)
        }
    }

    @Test
    fun testJwtSuccess() {
        withApplication {
            application.configureServerJwtNative()

            val token = getToken()
            println(token)

            val response = handleRequestWithToken(token)

            assertTrue(response.requestHandled)
            assertEquals(HttpStatusCode.OK, response.response.status())
            assertNotNull(response.response.content)
        }
    }

    @Test
    fun testJwtSuccessWithCustomScheme() {
        withApplication {
            application.configureServerJwtNative {
                authSchemes("Bearer", "Token")
            }

            val token = getToken(scheme = "Token")

            val response = handleRequestWithToken(token)

            assertTrue(response.requestHandled)
            assertEquals(HttpStatusCode.OK, response.response.status())
            assertNotNull(response.response.content)
        }
    }

    @Test
    fun testJwtSuccessWithCustomSchemeWithDifferentCases() {
        withApplication {
            application.configureServerJwtNative {
                authSchemes("Bearer", "tokEN")
            }

            val token = getToken(scheme = "TOKen")

            val response = handleRequestWithToken(token)

            assertTrue(response.requestHandled)
            assertEquals(HttpStatusCode.OK, response.response.status())
            assertNotNull(response.response.content)
        }
    }

    @Test
    fun testJwtAlgorithmMismatch() {
        withApplication {
            application.configureServerJwtNative()
            val token = runBlocking {
                JWS.sign(makeJWT {
                    singleAudience = this@JWTAuthTest.audience
                    issuer = this@JWTAuthTest.issuer
                }, HS256, { HmacStringKey("false") })
            }
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwtAudienceMismatch() {
        withApplication {
            application.configureServerJwtNative()
            val token = signJwt {
                singleAudience = "wrong"
                issuer = this@JWTAuthTest.issuer
            }
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwtIssuerMismatch() {
        withApplication {
            application.configureServerJwtNative()
            //val token = JWT.create().withAudience(audience).withIssuer("wrong").sign(algorithm)
            val token = signJwt {
                singleAudience = this@JWTAuthTest.audience
                issuer = "wrong"
            }
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwkNoAuth() {
        withApplication {
            application.configureServerJwk()

            val response = handleRequest {
                uri = "/"
            }

            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwkSuccess() {
        withApplication {
            application.configureServerJwk()

            val token = getJwkToken()

            val response = handleRequestWithToken(token)

            assertTrue(response.requestHandled)
            assertEquals(HttpStatusCode.OK, response.response.status())
            assertNotNull(response.response.content)
        }
    }

    @Test
    fun testJwkSuccessNoIssuer() {
        withApplication {
            application.configureServerJwkNoIssuer()

            val token = getJwkToken()

            val response = handleRequestWithToken(token)

            assertTrue(response.requestHandled)
            assertEquals(HttpStatusCode.OK, response.response.status())
            assertNotNull(response.response.content)
        }
    }

    @Test
    fun testJwtAuthSchemeMismatch() {
        withApplication {
            application.configureServerJwtNative()
            val token = getToken().removePrefix("Bearer ")
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwtAuthSchemeMismatch2() {
        withApplication {
            application.configureServerJwtNative()
            val token = getToken("Token")
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwtAuthSchemeMistake() {
        withApplication {
            application.configureServerJwtNative()
            val token = getToken().replace("Bearer", "Bearer:")
            val response = handleRequestWithToken(token)
            verifyResponseBadRequest(response)
        }
    }

    @Test
    fun testJwtBlobPatternMismatch() {
        withApplication {
            application.configureServerJwtNative()
            val token = getToken().let {
                val i = it.length - 2
                it.replaceRange(i..i + 1, " ")
            }
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwkAuthSchemeMismatch() {
        withApplication {
            application.configureServerJwk()
            val token = getJwkToken(false)
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwkAuthSchemeMistake() {
        withApplication {
            application.configureServerJwk()
            val token = getJwkToken(true).replace("Bearer", "Bearer:")
            val response = handleRequestWithToken(token)
            verifyResponseBadRequest(response)
        }
    }

    @Test
    fun testJwkBlobPatternMismatch() {
        withApplication {
            application.configureServerJwk()
            val token = getJwkToken(true).let {
                val i = it.length - 2
                it.replaceRange(i..i + 1, " ")
            }
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwkKidMismatch() {
        withApplication {
            application.configureServerJwk()

            val token = "Bearer " + signJwt ("wrong") {
                singleAudience = this@JWTAuthTest.audience
                issuer = this@JWTAuthTest.issuer
            }

            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwkInvalidToken() {
        withApplication {
            application.configureServerJwk()
            val token = "Bearer wrong"
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwkInvalidTokenCustomChallenge() {
        withApplication {
            application.configureServerJwk(challenge = true)
            val token = "Bearer wrong"
            val response = handleRequestWithToken(token)
            verifyResponseForbidden(response)
        }
    }


    @Test
    fun authHeaderFromCookie(): Unit = withApplication {
        application.configureServer {
            jwtNative {
                this@jwtNative.realm = this@JWTAuthTest.realm
                authHeader { call ->
                    call.request.cookies["JWT"]?.let { parseAuthorizationHeader(it) }
                }
                validator(makeJwtVerifier())
                keyProvider = getJwkProviderMock()
            }
        }

        val token = getToken()

        val response = handleRequest {
            uri = "/"
            addHeader(HttpHeaders.Cookie, "JWT=${token.encodeURLParameter()}")
        }

        assertTrue(response.requestHandled)
        assertEquals(HttpStatusCode.OK, response.response.status())
        assertNotNull(response.response.content)
    }

    private fun verifyResponseUnauthorized(response: TestApplicationCall) {
        assertTrue(response.requestHandled)
        assertEquals(HttpStatusCode.Unauthorized, response.response.status())
        assertNull(response.response.content)
    }

    private fun verifyResponseBadRequest(response: TestApplicationCall) {
        assertTrue(response.requestHandled)
        assertEquals(HttpStatusCode.BadRequest, response.response.status())
        assertNull(response.response.content)
    }

    private fun verifyResponseForbidden(response: TestApplicationCall) {
        assertTrue(response.requestHandled)
        assertEquals(HttpStatusCode.Forbidden, response.response.status())
        assertNull(response.response.content)
    }

    private fun TestApplicationEngine.handleRequestWithToken(token: String): TestApplicationCall {
        return handleRequest {
            uri = "/"
            addHeader(HttpHeaders.Authorization, token)
        }
    }

    private fun Application.configureServerJwk(challenge: Boolean = false) = configureServer {
        jwtNative {
            this@jwtNative.realm = this@JWTAuthTest.realm
            keyProvider(getJwkProviderMock())
            validator {
                //requireKeyId(kid)
                validateSignature()
                requireIssuer(issuer)
                requireAudience(audience)
            }
            if (challenge) {
                challenge { defaultScheme, realm ->
                    call.respond(
                        ForbiddenResponse(
                            HttpAuthHeader.Parameterized(
                                defaultScheme,
                                mapOf(HttpAuthHeader.Parameters.Realm to realm)
                            )
                        )
                    )
                }
            }
        }
    }

    private fun Application.configureServerJwkNoIssuer() = configureServer {
        jwtNative {
            this@jwtNative.realm = this@JWTAuthTest.realm
            keyProvider(getJwkProviderMock())
            validator { requireAudience(audience) }
        }
    }

    private fun Application.configureServerJwtNative(extra: JWTNativeAuthenticationProvider.Configuration.() -> Unit = {}) = configureServer {
        jwtNative {
            this@jwtNative.realm = this@JWTAuthTest.realm
            keyProvider(getJwkProviderMock())
            validator(makeJwtVerifier())
            extra()
        }
    }

    private fun Application.configureServer(authBlock: (Authentication.Configuration.() -> Unit)) {
        install(Authentication) {
            authBlock(this)
        }
        routing {
            authenticate {
                get("/") {
                    val principal = call.authentication.principal<JwtPrincipal>()!!
                    call.respondText("Secret info from ${principal.issuer}")
                }
            }
        }
    }

    //private val algorithm = Algorithm.HMAC256("secret")
    private val keyPair = KeyPairGenerator.getInstance("RSA").apply {
        initialize(2048, SecureRandom())
    }.generateKeyPair()
    //private val jwkAlgorithm = Algorithm.RSA256(keyPair.public as RSAPublicKey, keyPair.private as RSAPrivateKey)
    private val jwkAlgorithm = RS256
    private val issuer = "https://jwt-provider-domain/"
    private val audience = "jwt-audience"
    private val realm = "ktor jwt auth test"

    private fun signJwt(keyId: String? = null, block: JwtBuilder.()->Unit): String {
        return runBlocking {
            JWS.sign(makeJWT(block), jwkAlgorithm, { JavaPrivateRSAKey(keyPair.private as RSAPrivateKey) }, keyId ?: kid)
        }
    }

    private fun makeJwtVerifier(): TokenValidatorFn = {
        requireAlgorithm(jwkAlgorithm)
        validateSignature()
        requireAudience(audience)
        requireIssuer(issuer)
    }

    private val kid = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg"

    private fun getJwkProviderMock(): KeyProvider {
        return {
            when (it) {
                kid -> JavaPublicRSAKey(keyPair.public as RSAPublicKey)
                else -> null
            }
        }
    }

    private fun getJwkToken(prefix: Boolean = true) = (if (prefix) "Bearer " else "") + runBlocking {
        JWS.sign(
            JWTPayload(
            JWTClaimsSet(
                audience = listOf(audience),
                issuer = issuer
            )
        ), jwkAlgorithm, { JavaPrivateRSAKey(keyPair.private as RSAPrivateKey) }, kid)
    }

    private fun getToken(scheme: String = "Bearer") = "$scheme " + runBlocking {
        JWS.sign(
            JWTPayload(
            JWTClaimsSet(
                audience = listOf(audience),
                issuer = issuer
            )
        ), jwkAlgorithm, { JavaPrivateRSAKey(keyPair.private as RSAPrivateKey) }, kid)
    }

}

