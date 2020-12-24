/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

public actual object JWSAlgorithmRegistry {
    internal actual val JWS_ALGORITHMS: Map<String, JwsAlgorithm> = error("TODO")
}
