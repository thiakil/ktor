/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

/**
 * Type of SHA used by various JWA algorithms
 */
internal enum class SHAType {
    SHA256,
    SHA384,
    SHA512,
}
