/*
 * Copyright 2014-2021 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt.algorithms

import io.ktor.jwt.*
import java.security.*
import java.security.interfaces.*
import kotlin.test.*

class TestRsaJvmCommon {
    @Test
    fun testJvmToJwk(){
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048, SecureRandom())
        }.generateKeyPair()

        //test public and private works
        var newJwk = JsonWebKey.RSA(
            privateKey = keyPair.private as RSAPrivateKey,
            publicKey = keyPair.public as RSAPublicKey
        )
        assert(newJwk.isValidPrivateKey)
        assert(newJwk.isValidPublicKey)

        //test just public (produces only a valid public key)
        newJwk = JsonWebKey.RSA(
            publicKey = keyPair.public as RSAPublicKey
        )

        assert(newJwk.isValidPublicKey)
        assertFalse(newJwk.isValidPrivateKey)

        //test just private, which should have enough info for the public
        newJwk = JsonWebKey.RSA(
            privateKey = keyPair.private as RSAPrivateKey,
        )
        assert(newJwk.isValidPrivateKey)
        assert(newJwk.isValidPublicKey)
    }

    @Test
    fun testJvmJwkCompatibility() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048, SecureRandom())
        }.generateKeyPair()

        val newJwk = JsonWebKey.RSA(
            privateKey = keyPair.private as RSAPrivateKey,
            publicKey = keyPair.public as RSAPublicKey
        )
        assert(newJwk.isValidPrivateKey)
        assert(newJwk.isValidPublicKey)

        val baseToken = makeJWT {
            issuer = "test-issuer"
            singleAudience = "test"
            subject = "test testerton"
        }

        val nativeKey = JavaRSAKey(keyPair)

        //test signing via native and verifying by jwk
        val jvmSigned = baseToken.signSync {
            key = nativeKey
            alg = RS256
        }
        assert(RS256.verify(JWT.decode(jvmSigned).signature!!, newJwk))

        //test signing via JWK and verifying via native
        val jwkSigned = baseToken.signSync {
            key = newJwk
            alg = RS256
        }
        assert(RS256.verify(JWT.decode(jwkSigned).signature!!, nativeKey))
    }
}
