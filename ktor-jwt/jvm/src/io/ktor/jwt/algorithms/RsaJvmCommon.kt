/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt.algorithms

import io.ktor.jwt.*
import io.ktor.util.*
import java.math.*
import java.security.*
import java.security.interfaces.*
import java.security.spec.*

public data class JavaRSAKey(val publicKey: RSAPublicKey? = null, val privateKey: RSAPrivateKey? = null): SigningKey {
    public constructor(keyPair: KeyPair): this(keyPair.public as RSAPublicKey?, keyPair.private as RSAPrivateKey?)
}

public fun JsonWebKey.RSA.toJavaRSAPublicKey(): RSAPublicKey {
    if (!this.isValidPublicKey) {
        throw UnsupportedKeyException("Not a valid RSA public key")
    }
    val modulus = BigInteger(1, this.modulus!!.decodeBase64UrlBytes())
    val exponent = BigInteger(1, this.exponent!!.decodeBase64UrlBytes())
    try {
        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent)) as RSAPublicKey
    } catch (e: InvalidKeySpecException) {
        throw UnsupportedKeyException(e.message ?: "InvalidKeySpecException", e)
    } catch (e: NoSuchAlgorithmException) {
        throw UnsupportedKeyException(e.message ?: "NoSuchAlgorithmException", e)
    }
}

public fun JsonWebKey.RSA.toJavaRSAPrivateKey(): RSAPrivateKey {
    if (!this.isValidPrivateKey) {
        throw UnsupportedKeyException("Not a valid RSA private key")
    }
    val modulus = BigInteger(1, this.modulus!!.decodeBase64UrlBytes())
    val exponent = BigInteger(1, this.privateExponent!!.decodeBase64UrlBytes())
    try {
        return KeyFactory.getInstance("RSA").generatePrivate(RSAPrivateKeySpec(modulus, exponent)) as RSAPrivateKey
    } catch (e: InvalidKeySpecException) {
        throw UnsupportedKeyException(e.message ?: "InvalidKeySpecException", e)
    } catch (e: NoSuchAlgorithmException) {
        throw UnsupportedKeyException(e.message ?: "NoSuchAlgorithmException", e)
    }
}
