/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt.algorithms

import io.ktor.jwt.*

/**
 * None algorithm, only useful for [JWS.sign] and it's Id
 */
public object None: JwsAlgorithm {
    override val jwaId: String = "none"

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        return signature.signature.isEmpty()
    }

    override fun sign(payload: String, key: SigningKey): String = ""
}
