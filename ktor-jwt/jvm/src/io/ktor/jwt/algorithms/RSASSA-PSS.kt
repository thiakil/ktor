/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt.algorithms

import io.ktor.jwt.SigningKey
import io.ktor.jwt.*
import io.ktor.util.*
import java.security.*
import java.security.spec.*

private val SHAType.mdName get() = when(this) {
    SHAType.SHA256 -> "SHA-256"
    SHAType.SHA384 -> "SHA-384"
    SHAType.SHA512 -> "SHA-512"
}
private val SHAType.mfgSpec get() = when(this) {
    SHAType.SHA256 -> MGF1ParameterSpec.SHA256
    SHAType.SHA384 -> MGF1ParameterSpec.SHA384
    SHAType.SHA512 -> MGF1ParameterSpec.SHA512
}
private val SHAType.saltLen get() = when(this) {
    SHAType.SHA256 -> 32
    SHAType.SHA384 -> 48
    SHAType.SHA512 -> 64
}

public sealed class RsassPssBase(override val jwaId: String, alg: SHAType): JwsAlgorithm {
    private val pssParameterSpec = PSSParameterSpec(alg.mdName, "MGF1", alg.mfgSpec, alg.saltLen, 1)

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val publicKey = when(key) {
            is JavaRSAKey -> key.publicKey ?: throw UnsupportedKeyException("No public key!")
            is JsonWebKey.RSA -> key.toJavaRSAPublicKey()
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance("RSASSA-PSS")
        s.setParameter(pssParameterSpec)
        s.initVerify(publicKey)
        s.update(signature.subject.toByteArray(Charsets.UTF_8))
        return s.verify(signature.signature)
    }

    override fun sign(payload: String, key: SigningKey): String {
        val privateKey = when(key) {
            is JavaRSAKey -> key.privateKey ?: throw UnsupportedKeyException("No private key!")
            is JsonWebKey.RSA -> key.toJavaRSAPrivateKey()
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance("RSASSA-PSS")
        s.setParameter(pssParameterSpec)
        s.initSign(privateKey, SecureRandom())
        s.update(payload.toByteArray(Charsets.UTF_8))
        return s.sign().encodeBase64Url()
    }
}

public object PS256: RsassPssBase("PS256", SHAType.SHA256)
public object PS384: RsassPssBase("PS384", SHAType.SHA384)
public object PS512: RsassPssBase("PS512", SHAType.SHA512)
