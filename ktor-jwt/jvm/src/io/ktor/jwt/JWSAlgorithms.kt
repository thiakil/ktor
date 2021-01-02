/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import io.ktor.jwt.algorithms.*

internal actual val JWS_ALGORITHMS: Map<String, JwsAlgorithm> = listOf(
    ES256, ES384, ES512,
    HS256, HS384, HS512,
    PS256, PS384, PS512,
    RS256, RS384, RS512
).map { Pair(it.jwaId, it) }.toMap()
