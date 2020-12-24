/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.auth.jwtnative.algorithms

import io.ktor.auth.jwtnative.*
import io.ktor.auth.jwtnative.SigningKey
import io.ktor.util.*
import java.math.*
import java.security.*
import java.security.interfaces.*
import java.security.spec.*

public data class JavaPublicRSAKey(val publicKey: RSAPublicKey): SigningKey
public data class JavaPrivateRSAKey(val privateKey: RSAPrivateKey): SigningKey

internal fun JsonWebKey.RSA.toJavaRSAPublicKey(): RSAPublicKey {
    if (!this.isValidPublicKey) {
        throw UnsupportedKeyException("Not a valid RSA public key")
    }
    val modulus = BigInteger(1, this.modulus!!.decodeBase64UrlBytes())
    val exponent = BigInteger(1, this.exponent!!.decodeBase64UrlBytes())
    try {
        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent)) as RSAPublicKey
    } catch (e: InvalidKeySpecException) {
        throw UnsupportedKeyException(e.message?:"InvalidKeySpecException", e)
    } catch (e: NoSuchAlgorithmException) {
        throw UnsupportedKeyException(e.message?:"NoSuchAlgorithmException", e)
    }
}
internal fun JsonWebKey.RSA.toJavaRSAPrivateKey(): RSAPrivateKey {
    if (!this.isValidPrivateKey) {
        throw UnsupportedKeyException("Not a valid RSA private key")
    }
    val modulus = BigInteger(1, this.modulus!!.decodeBase64UrlBytes())
    val exponent = BigInteger(1, this.privateExponent!!.decodeBase64UrlBytes())
    try {
        return KeyFactory.getInstance("RSA").generatePrivate(RSAPrivateKeySpec(modulus, exponent)) as RSAPrivateKey
    } catch (e: InvalidKeySpecException) {
        throw UnsupportedKeyException(e.message?:"InvalidKeySpecException", e)
    } catch (e: NoSuchAlgorithmException) {
        throw UnsupportedKeyException(e.message?:"NoSuchAlgorithmException", e)
    }
}

public sealed class RSABase(override val jwaId: String, alg: SHAType): JwsAlgorithm {
    private val javaSigAlg = when(alg) {
        SHAType.SHA256 -> "SHA256withRSA"
        SHAType.SHA384 -> "SHA384withRSA"
        SHAType.SHA512 -> "SHA512withRSA"
    }
    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val publicKey = when(key) {
            is JavaPublicRSAKey -> key.publicKey
            is JsonWebKey.RSA -> key.toJavaRSAPublicKey()
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance(javaSigAlg)
        s.initVerify(publicKey)
        s.update(signature.subject.toByteArray(Charsets.UTF_8))
        return s.verify(signature.signature)
    }

    override fun sign(payload: String, key: SigningKey): String {
        val privateKey = when(key) {
            is JavaPrivateRSAKey -> key.privateKey
            is JsonWebKey.RSA -> key.toJavaRSAPrivateKey()
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance(javaSigAlg)
        s.initSign(privateKey, SecureRandom())
        s.update(payload.toByteArray(Charsets.UTF_8))
        return s.sign().encodeBase64Url()
    }
}

public object RS256: RSABase("RS256", SHAType.SHA256)
public object RS384: RSABase("RS384", SHAType.SHA384)
public object RS512: RSABase("RS512", SHAType.SHA512)
