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

            val token = getHmacToken()
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

            val token = getHmacToken()
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

            val token = getHmacToken(scheme = "Token")

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

            val token = getHmacToken(scheme = "TOKen")

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
            val token = getHmacToken().removePrefix("Bearer ")
            val response = handleRequestWithToken(token, true)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwtAuthSchemeMismatch2() {
        withApplication {
            application.configureServerJwtNative()
            val token = getHmacToken("Token")
            val response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwtAuthSchemeMistake() {
        withApplication {
            application.configureServerJwtNative()
            val token = getHmacToken().replace("Bearer", "Bearer:")
            val response = handleRequestWithToken(token)
            verifyResponseBadRequest(response)
        }
    }

    @Test
    fun testJwtBlobPatternMismatch() {
        withApplication {
            application.configureServerJwtNative()
            val token = getHmacToken().let {
                val i = it.length - 2
                it.replaceRange(i..i + 1, " ")
            }
            val response = handleRequestWithToken(token, true)
            verifyResponseUnauthorized(response)
        }
    }

    @Test
    fun testJwkKidMismatch() {
        withApplication {
            application.configureServerJwk()

            val token = "Bearer " + makeJWT {
                singleAudience = JWTAuthTest.audience
                issuer = JWTAuthTest.issuer
            }.signSync {
                key = javaRsaKey
                keyId = "wrong"
                alg = jwkAlgorithm
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

    /**
     * Verify that a successful validation succeeds, and a failed one prevents authorization
     */
    @Test
    fun testValidatorFailsAuth() {
        withApplication {
            var validationResult = true
            application.configureServer {
                jwtNative {
                    validator {
                        if (!validationResult) {
                            fail("custom failure message")
                        }
                    }
                }
            }
            val token = getHmacToken()
            var response = handleRequestWithToken(token)
            assertTrue(response.requestHandled)
            assertEquals(HttpStatusCode.OK, response.response.status())

            validationResult = false
            response = handleRequestWithToken(token)
            verifyResponseUnauthorized(response)
            val authContext = response.response.call.authentication
            assertNotEquals(0, authContext.allFailures.size)
            val failure = authContext.allFailures.find { it is AuthenticationFailedCause.InvalidCredentials }
            assertNotNull(failure)
        }
    }

    @Test
    fun authHeaderFromCookie(): Unit = withApplication {
        application.configureServer {
            jwtNative {
                this@jwtNative.realm = JWTAuthTest.realm
                authHeader { call ->
                    call.request.cookies["JWT"]?.let { parseAuthorizationHeader(it) }
                }
                validator(makeJwtVerifier())
                keyProvider = getJwkProviderMock()
            }
        }

        val token = getHmacToken()

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

    private fun TestApplicationEngine.handleRequestWithToken(token: String, intentionalBadHeader: Boolean = false): TestApplicationCall {
        if (!intentionalBadHeader) {
            assertEquals(2, token.split(" ").size, "Bad auth header value: <$token>")
        }
        return handleRequest {
            uri = "/"
            addHeader(HttpHeaders.Authorization, token)
        }
    }

    private fun Application.configureServerJwk(challenge: Boolean = false) = configureServer {
        jwtNative {
            this@jwtNative.realm = JWTAuthTest.realm
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

    private fun Application.configureServerJwtNative(extra: JWTNativeAuthenticationProvider.Configuration.() -> Unit = {}) = configureServer {
        jwtNative {
            this@jwtNative.realm = JWTAuthTest.realm
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

    companion object {

        private val algorithm = HS256
        private val hmacKey = HmacStringKey("secret")
        private val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048, SecureRandom())
        }.generateKeyPair()
        private val javaRsaKey = JavaRSAKey(keyPair)

        //private val jwkAlgorithm = Algorithm.RSA256(keyPair.public as RSAPublicKey, keyPair.private as RSAPrivateKey)
        private val jwkAlgorithm = RS256
        private const val issuer = "https://jwt-provider-domain/"
        private const val audience = "jwt-audience"
        private const val realm = "ktor jwt auth test"

        private fun makeJwtVerifier(): TokenValidatorFn = {
            //requireAlgorithm(algorithm)
            validateSignature()
            requireAudience(audience)
            requireIssuer(issuer)
        }

        private const val kid = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg"

        private fun getJwkProviderMock(): KeyProvider {
            return {
                when (it) {
                    kid -> javaRsaKey
                    "wrong" -> null
                    else -> hmacKey
                }
            }
        }

        /** RSA */
        private fun getRSAToken(prefix: Boolean = true) = (if (prefix) "Bearer " else "") + runBlocking {
            makeJWT {
                singleAudience = this@Companion.audience
                issuer = this@Companion.issuer
            }.sign {
                alg = jwkAlgorithm
                key = javaRsaKey
                keyId = kid
            }
        }

        /** HMAC */
        private fun getHmacToken(scheme: String = "Bearer") = "$scheme " + runBlocking {
            makeJWT {
                singleAudience = this@Companion.audience
                issuer = this@Companion.issuer
            }.sign {
                alg = this@Companion.algorithm
                key = hmacKey
            }
        }
    }

}

