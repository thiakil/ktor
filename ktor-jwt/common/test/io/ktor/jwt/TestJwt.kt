/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt

import io.ktor.jwt.*
import io.ktor.util.date.*
import kotlinx.serialization.json.*
import kotlin.test.*

class TestJwt {
    private val basicEncodedJWT = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    @Test
    fun decodeBasic() {
        val decoded = JWT.decode(basicEncodedJWT)
        assertEquals("HS256", decoded.header.algorithm, "Header parse failed")
        assertEquals("JWT", decoded.header.type, "Header parse failed")
        assertEquals("joe", decoded.payload.claimsSet.issuer)
        assertEquals(GMTDate(1300819380L * 1000), decoded.payload.claimsSet.expiresAt)
        assertTrue(decoded.payload.unknownClaims.containsKey("http://example.com/is_root"))
        val isRoot = decoded.payload.unknownClaims["http://example.com/is_root"]
        assertTrue(isRoot is JsonPrimitive)
        assertEquals("true", isRoot.content)
    }

    @Test
    fun decodeUnsigned() {
        val decoded = JWT.decode("eyJhbGciOiJub25lIn0." +
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.")
        assertEquals("none", decoded.header.algorithm)
        assertEquals("joe", decoded.payload.claimsSet.issuer)
        assertNull(decoded.signature)
    }
}
