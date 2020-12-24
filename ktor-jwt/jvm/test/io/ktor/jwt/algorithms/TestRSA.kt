/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt.algorithms

import io.ktor.jwt.*
import io.ktor.util.*
import kotlinx.coroutines.*
import kotlinx.serialization.*
import java.security.*
import java.security.interfaces.*
import java.security.spec.*
import kotlin.test.*

class TestRSA {

    private val publicKey: RSAPublicKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKeyPEM.decodeBase64Bytes())) as RSAPublicKey

    private val privateKey: RSAPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKeyPEM.decodeBase64Bytes())) as RSAPrivateKey


    @Test
    fun testRSASignature() {
        val jwt = JWT.decode(encodedJwt)
        assertEquals("RS256", jwt.header.algorithm)
        val key = JavaRSAKey(publicKey)
        assertTrue(RS256.verify(jwt.signature!!, key))
    }

    @Test
    fun testJWKRSASig() {
        val jwt = JWT.decode(tokenSignedbyJwk)
        assertEquals("RS256", jwt.header.algorithm)
        val jwk = JsonWebKey.format.decodeFromString<JsonWebKey>(testJWK)
        assertTrue(RS256.verify(jwt.signature!!, jwk))
    }

    @Test
    fun testSignWithJwk(){
        val jwk = JsonWebKey.format.decodeFromString<JsonWebKey>(testJWK)
        assertTrue(jwk is JsonWebKey.RSA)
        assertTrue(jwk.isValidPrivateKey)
        val signed = runBlocking { JWS.sign(baseToken, RS256, { jwk }) }
        assertTrue(RS256.verify(JWT.decode(signed).signature!!, jwk))
    }

    @Test
    fun testSignAndVerify(){
        val signed = runBlocking { JWS.sign(baseToken, RS256, { JavaRSAKey(privateKey = privateKey) }) }
        assertTrue(RS256.verify(JWT.decode(signed).signature!!, JavaRSAKey(publicKey)))
    }

    @Test
    fun testSignVerifyLoop() {
        val key = JsonWebKey.format.decodeFromString<JsonWebKey>(testJWK)
        AlgorithmHelper.testSelfSignVerify(baseToken, RS256, key)
        AlgorithmHelper.testSelfSignVerify(baseToken, RS384, key)
        AlgorithmHelper.testSelfSignVerify(baseToken, RS512, key)
    }

    companion object {
        private val baseToken = makeJWT {
            issuer = "test-issuer"
            singleAudience = "test"
            subject = "test testerton"
        }
        private val publicKeyPEM = """
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
            vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
            aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
            tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
            e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
            V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
            MwIDAQAB""".trimIndent().replace("\r", "").replace("\n", "")
        private val privateKeyPEM = """
            MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCfPKKzVmN80HRsGAoUxK++RO3C
            W8GxomrtLnAD6TN5U5WlVbCRZ1WFrizfxcz+lr/Kvjtq/v7PdVOa8NHIAdxpP3bCFEQWku/1yPmV
            N4lKJvKv8yub9i2MJlVaBo5giHCtfAouo+v/XWKdawCR8jK28dZPFlgRxcuABcW5S5pLe4X2ASI1
            DDMZNTW/QWqSpMGvgHydbccI3jtdS7S3xjR76V/izg7FBrBYPv0n3/l3dHLS9tXcCbUW0YmIm87B
            Gwh9UKEOlhK1NwdMIyq29ZtXovXUFaSnMZdJbge/jepr4ZJg4PZBTrwxvn2hKTY4H4G04ukmh+Zs
            YQaC+bDIIj0zAgMBAAECggEAKIBGrbCSW2O1yOyQW9nvDUkA5EdsS58Q7US7bvM4iWpuDIBwCXur
            7/VuKnhn/HUhURLzj/JNozynSChqYyG+CvL+ZLy82LUE3ZIBkSdv/vFLFt+VvvRtf1EcsmoqenkZ
            l7aN7HD7DJeXBoz5tyVQKuH17WW0fsi9StGtCcUl+H6KzV9Gif0Kj0uLQbCg3THRvKuueBTwCTdj
            oP0PwaNADgSWb3hJPeLMm/yII4tIMGbOw+xd9wJRl+ZN9nkNtQMxszFGdKjedB6goYLQuP0WRZx+
            YtykaVJdM75bDUvsQar49Pc21Fp7UVk/CN11DX/hX3TmTJAUtqYADliVKkTbCQKBgQDLU48tBxm3
            g1CdDM/PZIEmpA3Y/m7e9eX7M1Uo/zDh4G/S9a4kkX6GQY2dLFdCtOS8M4hR11Io7MceBKDidjor
            TZ5zJPQ8+b9Rm+1GlaucGNwRW0cQk2ltT2ksPmJnQn2xvM9T8vE+a4A/YGzwmZOfpoVGykWs/tbS
            zU2aTaOybQKBgQDIfRf6OmirGPh59l+RSuDkZtISF/51mCV/S1M4DltWDwhjC2Y2T+meIsb/Mjtz
            4aVNz0EHB8yvn0TMGr94Uwjv4uBdpVSwz+xLhHL7J4rpInH+i0gxa0N+rGwsPwI8wJG95wLY+Kni
            5KCuXQw55uX1cqnnsahpRZFZEerBXhjqHwKBgBmEjiaHipm2eEqNjhMoOPFBi59dJ0sCL2/cXGa9
            yEPA6Cfgv49FV0zAM2azZuwvSbm4+fXTgTMzrDW/PPXPArPmlOk8jQ6OBY3XdOrz48q+b/gZrYyO
            A6A9ZCSyW6U7+gxxds/BYLeFxF2v21xC2f0iZ/2faykv/oQMUh34en/tAoGACqVZ2JexZyR0TUWf
            3X80YexzyzIq+OOTWicNzDQ29WLm9xtr2gZ0SUlfd72bGpQoyvDuawkm/UxfwtbIxALkvpg1gcN9
            s8XWrkviLyPyZF7H3tRWiQlBFEDjnZXa8I7pLkROCmdp3fp17cxTEeAI5feovfzZDH39MdWZuZrd
            h9ECgYBTEv8S7nK8wrxIC390kroV52eBwzckQU2mWa0thUtaGQiU1EYPCSDcjkrLXwB72ft0dW57
            KyWtvrB6rt1ORgOLeI5hFbwdGQhCHTrAR1vG3SyFPMAm+8JB+sGOD/fvjtZKx//MFNweKFNEF0C/
            o6Z2FXj90PlgF8sCQut36ZfuIQ==""".trimIndent().replace("\r", "").replace("\n", "")
        private val encodedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA"

        private val testJWK = """
            {"kty":"RSA",
      "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
      "e":"AQAB",
      "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
      "p": "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
      "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
      "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
      "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
      "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
     }
        """.trimIndent()
        private val tokenSignedbyJwk = """
            eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw
        """.trimIndent()
    }
}
