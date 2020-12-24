/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.auth.jwtnative.algorithms

import io.ktor.auth.jwtnative.*
import kotlinx.serialization.*
import kotlin.test.*

/**
 * Created by Thiakil on 20/12/2020.
 */
class TestECDSA {
    @Test
    fun testES256Verify() {
        val jwt = JWT.decode(encodedJwt)
        assertEquals(ES256.jwaId, jwt.header.algorithm)
        assertTrue(ES256.verify(jwt.signature!!, ecKey))
    }

    // https://tools.ietf.org/html/rfc7515#appendix-A.3
    private val ecKey = JsonWebKey.format.decodeFromString<JsonWebKey.EllipticCurve>("""{"kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
     }""")
    private val encodedJwt = "eyJhbGciOiJFUzI1NiJ9" +
        "." +
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
        "." +
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
}
