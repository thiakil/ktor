/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.auth.jwtnative.algorithms

import io.ktor.auth.jwtnative.*
import io.ktor.util.*
import kotlinx.serialization.*
import java.security.*
import java.security.interfaces.*
import java.security.spec.*
import kotlin.test.*

/**
 * Created by Thiakil on 20/12/2020.
 */
class TestRSAPSS {

    private fun getPublicKey(): PublicKey {
        val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(publicKeyPEM.decodeBase64Bytes())
        return keyFactory.generatePublic(keySpec)
    }

    @Test
    fun testRSAPSSSignature() {
        val jwt = JWT.decode(encodedJwt)
        assertEquals("PS256", jwt.header.algorithm)
        val key = JavaPublicRSAKey(getPublicKey() as RSAPublicKey)
        assertTrue(PS256.verify(jwt.signature!!, key))
    }

    companion object {
        private val publicKeyPEM = """
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJUFP/OFDmrGA3CoNERk
            LBGO+MssE5P849J62gWakijtweRf59EIDVG+cv7Nyx1EUiChoyTl2O2e347qjNLc
            UhKh1oj1jAhB1HREBgvuj+cJX/IaDrLrqCUFN3B2nEcLoqAwNltXCSDqPElHxKwE
            50AwZo7fW7Y+go5YbSdVGh6yQloq1TgAwihgrpH72juycQdtCisyrNKNZfrtRfvs
            58WuA4E7Ru3OR3QQva6RkxQL0oQoASwBDVwQOSlAgxnJwBptgqQH6eN0TWYH7dBs
            ojtSVcVGzFw3Lcorc0jllKIScZ5wvhGuQ+bDpUGUvEekvGM2RvYmqrx4kg2hc68a
            UwIDAQAB""".trimIndent().replace("\r", "").replace("\n", "")
        private val privateKeyPEM = """
            MIIEpAIBAAKCAQEAzJUFP/OFDmrGA3CoNERkLBGO+MssE5P849J62gWakijtweRf
            59EIDVG+cv7Nyx1EUiChoyTl2O2e347qjNLcUhKh1oj1jAhB1HREBgvuj+cJX/Ia
            DrLrqCUFN3B2nEcLoqAwNltXCSDqPElHxKwE50AwZo7fW7Y+go5YbSdVGh6yQloq
            1TgAwihgrpH72juycQdtCisyrNKNZfrtRfvs58WuA4E7Ru3OR3QQva6RkxQL0oQo
            ASwBDVwQOSlAgxnJwBptgqQH6eN0TWYH7dBsojtSVcVGzFw3Lcorc0jllKIScZ5w
            vhGuQ+bDpUGUvEekvGM2RvYmqrx4kg2hc68aUwIDAQABAoIBADcrisZjvAKWzb54
            v4uU0/TEaWtzkvfWpVCk3sdz0mrPCcsLdMeVqde5ryPgzguT4WxKa3yNA0T8U6dT
            KbJ/XLXvW2B4/8rbITGThxKgXh3FftQ2fEtxebaXATChrgLX7+3TyByohjCqhTBr
            zKRfhVT9jO/jYJ2haHsZuwP4ou0PVXGEnq2fR3neIf+kQxukWXdQejjOT6Idj3I8
            A3rU1hPgP7DSm27pQrl2iKCjW5pHGRqLiZ59Bg0KHkbdHByYpKdSEpfChNQsmv7N
            5SclLGmVeBj3ocg2fZv0vQABCNrVrM/pyclbcOFkKQVKg5mSF5o5EUl7J8AnuFnZ
            7p9vG50CgYEA8+gDspE5e5cPiumczeWJ3cDAvr5GNbhUQ5YSHBDjhc7uPI00b2sI
            GXk5SRvFv5rR4S5VwZSryeYxOpMjw9L1PIgCEtSiNVXlMU7V04XF7+Qf5/+UO5jA
            Q5UIlAtAMWM7hx34mNMPYay/IodZfGEEUntB0Zj2B1UuD0bLvFX6ZB8CgYEA1rnZ
            x8b9Vpb+cgPCwPU3e2TGJ73VLbv2gzvHkFps/S4OrGSlT2sbePUtCh2vBY5VkiYY
            R3gWNOgrdcexgOwDP0Eb1s+gBqukD7Yw1hn6DaHIkOWGMn6LDrLnXm0f/ZGFuJOV
            P32Zy0GzPnQE6/sHgqiZ799LLEHt+cuAz5B5Y00CgYEAn1fBKqSDmEFdDxSFs2G1
            CuFFSpfGCIxuyGS/WgSSj7VboMVjLzMObI3spd11+DIt0V3S+o+lF1bCbJD5+ZHV
            UwFL0X+GpS+Ddw4Y1YJ8iLdRPOCUt8aYPM6ddxJOkrVQi3pCEZ05XEdd6zHffUlo
            aHZLzqGOgcXdPG+05EqLNWMCgYEAhC1HR9jQHbs4ycpS2iCYlJaF+/S5AzwPFN15
            jPx81qTBV5FkySxvbtfNb8qx8EObnSliDKx5TvwTtJ7GP0wI+6kCkAqiwThq91j5
            WvIGoNmT8s22++I1i0jJb7DQ3m/z1pjSaJDSWPIKeklEtlaCWwWaLLRRO98htIB2
            vE58yokCgYBMivQtR/rDp9H8ou1UAATZlFel06oKBankM0pGHej+3m7FgRZjRXvD
            hV5Y9eA9322+e1hdZVwUiDP/RGSlUXno65tlUVOznR2bz/XFg3+Q8vquYHVmTjtj
            PLoW+qf7I2MEnUzTgt/wkXZHXJ5Pzq49n7I8NXFhVMDxNCU7Hgb8TA==""".trimIndent().replace("\r", "").replace("\n", "")
        private val encodedJwt =
            "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.FKxYGyhnJr1S_7J6KEgtGL4xalmxn6RQSJTuHGGQy2YYD_w8uvWSngFweA9mKEgEWymy4uG3WveS5ZSMi_nJmRodUnlhczqsgpOpTffU9_432MjkyWBOGwVYXiK_dLfG3BmQS3fZi-XOLfKj_JfUcKL_fL7ueO-RclvYzrBfIv0uWifblLkrjN_G7Zxj1dUG-XUm1j-reMbtYx0n80fUYEmSDKB1Kkng8S4y1IOuYF6ViLMisrQwlFeGxvwKIpEiVEmVCij-D8xsQocrK881hyvoniRS5Uh9w2gobc2k65rInfV9o4lM2HFJLuzWYEY7rdnzkyohMtS57DHbjwPuBw"
    }
}
