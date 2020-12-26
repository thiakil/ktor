/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import kotlinx.serialization.*

/**
 * Data class impl of [JOSEHeader]
 */
@Serializable
public data class JOSEHeaderData(
    @SerialName("typ")
    override val type: String? = null,

    @SerialName("alg")
    override val algorithm: String,

    @SerialName("jku")
    override val jwkSetUrl: String? = null,

    @SerialName("jwk")
    override val jsonWebKey: JsonWebKey? = null,

    @SerialName("kid")
    override val keyId: String? = null,

    @SerialName("x5u")
    override val x509Url: String? = null,

    @SerialName("x5c")
    override val x509CertChain: List<String>? = null,

    @SerialName("cty")
    override val contentType: String? = null,

    @SerialName("crit")
    override val critical: List<String>? = null
) : JOSEHeader
