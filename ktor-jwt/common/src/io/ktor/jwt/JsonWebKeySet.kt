/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import kotlinx.serialization.*

@Serializable
public class JsonWebKeySet(public val keys: List<JsonWebKey>): List<JsonWebKey> by keys {

    public companion object {
        public fun decodeFromString(jwkSet: String): JsonWebKeySet = JsonWebKey.format.decodeFromString(jwkSet)
    }
}
