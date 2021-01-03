/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import kotlinx.coroutines.*
import kotlin.test.*

object AlgorithmHelper {
    fun testSelfSignVerify(jwt: JWTPayload, algorithm: JwsAlgorithm, keyIn: SigningKey) {
        val signed = jwt.signSync {
            key = keyIn
            alg = algorithm
        }
        assertTrue(algorithm.verify(JWT.decode(signed).signature!!, keyIn))
    }
}
