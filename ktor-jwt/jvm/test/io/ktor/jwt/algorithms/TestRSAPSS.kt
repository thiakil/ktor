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

class TestRSAPSS {

    private fun getPublicKey(): RSAPublicKey {
        val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(publicKeyPEM.decodeBase64Bytes())
        return keyFactory.generatePublic(keySpec) as RSAPublicKey
    }

    private fun getPrivateKey(): RSAPrivateKey {
        val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")
        val keySpec = PKCS8EncodedKeySpec(privateKeyPEM.decodeBase64Bytes())
        return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
    }

    @Test
    fun testRSAPSSSignature() {
        val jwt = JWT.decode(encodedJwt)
        assertEquals("PS256", jwt.header.algorithm)
        val key = JavaRSAKey(getPublicKey())
        assertTrue(PS256.verify(jwt.signature!!, key))
    }

    @Test
    fun testSignAndVerify(){
        val signed = runBlocking { JWS.sign(baseToken, PS256, { JavaRSAKey(privateKey = getPrivateKey()) }) }
        assertTrue(PS256.verify(JWT.decode(signed).signature!!, JavaRSAKey(getPublicKey())))
    }

    @Test
    fun testSignVerifyLoop() {
        val key = JavaRSAKey(getPublicKey(), getPrivateKey())
        AlgorithmHelper.testSelfSignVerify(baseToken, PS256, key)
        AlgorithmHelper.testSelfSignVerify(baseToken, PS384, key)
        AlgorithmHelper.testSelfSignVerify(baseToken, PS512, key)

        val jwk = JsonWebKey.format.decodeFromString<JsonWebKey>(rsaJwk)
        AlgorithmHelper.testSelfSignVerify(baseToken, PS256, jwk)
        AlgorithmHelper.testSelfSignVerify(baseToken, PS384, jwk)
        AlgorithmHelper.testSelfSignVerify(baseToken, PS512, jwk)
    }

    companion object {
        private val baseToken = makeJWT {
            issuer = "test-issuer"
            singleAudience = "test"
            subject = "test testerton"
        }
        private val publicKeyPEM = """
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJUFP/OFDmrGA3CoNERk
            LBGO+MssE5P849J62gWakijtweRf59EIDVG+cv7Nyx1EUiChoyTl2O2e347qjNLc
            UhKh1oj1jAhB1HREBgvuj+cJX/IaDrLrqCUFN3B2nEcLoqAwNltXCSDqPElHxKwE
            50AwZo7fW7Y+go5YbSdVGh6yQloq1TgAwihgrpH72juycQdtCisyrNKNZfrtRfvs
            58WuA4E7Ru3OR3QQva6RkxQL0oQoASwBDVwQOSlAgxnJwBptgqQH6eN0TWYH7dBs
            ojtSVcVGzFw3Lcorc0jllKIScZ5wvhGuQ+bDpUGUvEekvGM2RvYmqrx4kg2hc68a
            UwIDAQAB""".trimIndent().replace("\r", "").replace("\n", "")
        private val privateKeyPEM = """
            MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMlQU/84UOasYDcKg0RGQsEY74
            yywTk/zj0nraBZqSKO3B5F/n0QgNUb5y/s3LHURSIKGjJOXY7Z7fjuqM0txSEqHWiPWMCEHUdEQG
            C+6P5wlf8hoOsuuoJQU3cHacRwuioDA2W1cJIOo8SUfErATnQDBmjt9btj6CjlhtJ1UaHrJCWirV
            OADCKGCukfvaO7JxB20KKzKs0o1l+u1F++znxa4DgTtG7c5HdBC9rpGTFAvShCgBLAENXBA5KUCD
            GcnAGm2CpAfp43RNZgft0GyiO1JVxUbMXDctyitzSOWUohJxnnC+Ea5D5sOlQZS8R6S8YzZG9iaq
            vHiSDaFzrxpTAgMBAAECggEANyuKxmO8ApbNvni/i5TT9MRpa3OS99alUKTex3PSas8Jywt0x5Wp
            17mvI+DOC5PhbEprfI0DRPxTp1Mpsn9cte9bYHj/ytshMZOHEqBeHcV+1DZ8S3F5tpcBMKGuAtfv
            7dPIHKiGMKqFMGvMpF+FVP2M7+NgnaFoexm7A/ii7Q9VcYSerZ9Hed4h/6RDG6RZd1B6OM5Poh2P
            cjwDetTWE+A/sNKbbulCuXaIoKNbmkcZGouJnn0GDQoeRt0cHJikp1ISl8KE1Cya/s3lJyUsaZV4
            GPehyDZ9m/S9AAEI2tWsz+nJyVtw4WQpBUqDmZIXmjkRSXsnwCe4Wdnun28bnQKBgQDz6AOykTl7
            lw+K6ZzN5YndwMC+vkY1uFRDlhIcEOOFzu48jTRvawgZeTlJG8W/mtHhLlXBlKvJ5jE6kyPD0vU8
            iAIS1KI1VeUxTtXThcXv5B/n/5Q7mMBDlQiUC0AxYzuHHfiY0w9hrL8ih1l8YQRSe0HRmPYHVS4P
            Rsu8VfpkHwKBgQDWudnHxv1Wlv5yA8LA9Td7ZMYnvdUtu/aDO8eQWmz9Lg6sZKVPaxt49S0KHa8F
            jlWSJhhHeBY06Ct1x7GA7AM/QRvWz6AGq6QPtjDWGfoNociQ5YYyfosOsudebR/9kYW4k5U/fZnL
            QbM+dATr+weCqJnv30ssQe35y4DPkHljTQKBgQCfV8EqpIOYQV0PFIWzYbUK4UVKl8YIjG7IZL9a
            BJKPtVugxWMvMw5sjeyl3XX4Mi3RXdL6j6UXVsJskPn5kdVTAUvRf4alL4N3DhjVgnyIt1E84JS3
            xpg8zp13Ek6StVCLekIRnTlcR13rMd99SWhodkvOoY6Bxd08b7TkSos1YwKBgQCELUdH2NAduzjJ
            ylLaIJiUloX79LkDPA8U3XmM/HzWpMFXkWTJLG9u181vyrHwQ5udKWIMrHlO/BO0nsY/TAj7qQKQ
            CqLBOGr3WPla8gag2ZPyzbb74jWLSMlvsNDeb/PWmNJokNJY8gp6SUS2VoJbBZostFE73yG0gHa8
            TnzKiQKBgEyK9C1H+sOn0fyi7VQABNmUV6XTqgoFqeQzSkYd6P7ebsWBFmNFe8OFXlj14D3fbb57
            WF1lXBSIM/9EZKVReejrm2VRU7OdHZvP9cWDf5Dy+q5gdWZOO2M8uhb6p/sjYwSdTNOC3/CRdkdc
            nk/Orj2fsjw1cWFUwPE0JTseBvxM""".trimIndent().replace("\r", "").replace("\n", "")
        private const val encodedJwt =
            "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.FKxYGyhnJr1S_7J6KEgtGL4xalmxn6RQSJTuHGGQy2YYD_w8uvWSngFweA9mKEgEWymy4uG3WveS5ZSMi_nJmRodUnlhczqsgpOpTffU9_432MjkyWBOGwVYXiK_dLfG3BmQS3fZi-XOLfKj_JfUcKL_fL7ueO-RclvYzrBfIv0uWifblLkrjN_G7Zxj1dUG-XUm1j-reMbtYx0n80fUYEmSDKB1Kkng8S4y1IOuYF6ViLMisrQwlFeGxvwKIpEiVEmVCij-D8xsQocrK881hyvoniRS5Uh9w2gobc2k65rInfV9o4lM2HFJLuzWYEY7rdnzkyohMtS57DHbjwPuBw"
        private val rsaJwk = """
            {"kty":"RSA",
          "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
          "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
          "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
          "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
          "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
          "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
          "alg":"RS256",
          "kid":"2011-04-29"}
        """.trimIndent()
    }
}
