/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt.algorithms

import io.ktor.jwt.*
import io.ktor.util.*
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*

public interface HmacKey: SigningKey {
    public val secretBytes: ByteArray
}

public class HmacByteKey(override val secretBytes: ByteArray): HmacKey

public data class HmacStringKey(val secret: String): HmacKey {
    override val secretBytes: ByteArray
        get() = secret.toByteArray(Charsets.UTF_8)
}

public sealed class HmacBase(override val jwaId: String, alg: SHAType): JwsAlgorithm {
    private val javaSigAlg = when(alg) {
        SHAType.SHA256 -> "HmacSHA256"
        SHAType.SHA384 -> "HmacSHA384"
        SHAType.SHA512 -> "HmacSHA512"
    }
    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        return MessageDigest.isEqual(doMac(key, signature.subject), signature.signature)
    }

    private fun doMac(key: SigningKey, subject: String): ByteArray {
        val keyBytes = when (key) {
            is JsonWebKey.Symmetric -> key.keyValue
            is HmacKey -> key.secretBytes
            else -> throw UnsupportedKeyException("Unknown key: " + key.javaClass.name)
        }
        val mac = Mac.getInstance(javaSigAlg)
        mac.init(SecretKeySpec(keyBytes, javaSigAlg))
        return mac.doFinal(subject.toByteArray(Charsets.UTF_8))
    }

    override fun sign(payload: String, key: SigningKey): String = doMac(key, payload).encodeBase64Url()
}

public object HS256: HmacBase("HS256", SHAType.SHA256)
public object HS384: HmacBase("HS384", SHAType.SHA384)
public object HS512: HmacBase("HS512", SHAType.SHA512)
