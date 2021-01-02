/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt.algorithms

import io.ktor.jwt.*
import org.jetbrains.annotations.*
import java.math.*
import java.security.*
import java.security.interfaces.*
import java.security.spec.*

public data class JavaRSAKey(val publicKey: RSAPublicKey? = null, val privateKey: RSAPrivateKey? = null): SigningKey {
    public constructor(keyPair: KeyPair): this(keyPair.public as RSAPublicKey?, keyPair.private as RSAPrivateKey?)
}

private fun ByteArray.toUintBigInteger(): BigInteger = BigInteger(1, this)

public fun JsonWebKey.RSA.toJavaRSAPublicKey(): RSAPublicKey {
    if (!this.isValidPublicKey) {
        throw UnsupportedKeyException("Not a valid RSA public key")
    }
    val modulus = this.modulus!!.toUintBigInteger()
    val exponent = this.exponent!!.toUintBigInteger()
    try {
        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent)) as RSAPublicKey
    } catch (e: InvalidKeySpecException) {
        throw UnsupportedKeyException(e.message ?: "InvalidKeySpecException", e)
    } catch (e: NoSuchAlgorithmException) {
        throw UnsupportedKeyException(e.message ?: "NoSuchAlgorithmException", e)
    }
}

/** try [java.security.KeyFactory.generatePrivate] with provided spec, returning null if it fails */
private fun KeyFactory.tryPrivateKeySpec(spec: KeySpec): PrivateKey? {
    return try {
        this.generatePrivate(spec)
    } catch (e: InvalidKeySpecException) {
        null
    }
}

public fun JsonWebKey.RSA.toJavaRSAPrivateKey(): RSAPrivateKey {
    if (!this.isValidPrivateKey) {
        throw UnsupportedKeyException("Not a valid RSA private key")
    }
    val modulus = this.modulus!!.toUintBigInteger()
    val publicExponent = this.exponent!!.toUintBigInteger()
    val privateExponent = this.privateExponent!!.toUintBigInteger()
    val firstPrimeFactor = this.firstPrimeFactor?.toUintBigInteger()
    val secondPrimeFactor = this.secondPrimeFactor?.toUintBigInteger()
    val firstFactorCRTExponent = this.firstFactorCRTExponent?.toUintBigInteger()
    val secondFactorCRTExponent = this.secondFactorCRTExponent?.toUintBigInteger()
    val firstCRTCoefficient = this.firstCRTCoefficient?.toUintBigInteger()
    val otherPrimesInfo = this.otherPrimesInfo?.map {
        RSAOtherPrimeInfo(it.primeFactor.toUintBigInteger(), it.factorCRTExponent.toUintBigInteger(), it.factorCRTCoefficient.toUintBigInteger())
    }?.toTypedArray()
    val keyFactory = try {
        KeyFactory.getInstance("RSA")
    } catch (e: NoSuchAlgorithmException) {
        throw UnsupportedKeyException(e.message ?: "RSA algorithm not found in JVM", e)
    }
    //try to generate the private key with fallback in the order of Multi-prime, CRT, modulus+privateExponent
    //partly redundant as JVM may fall back internally as the first two share the common basic RSA interface
    //i.e. if a JWK has Other Primes Info, we'll get a basic modulus+privateExponent version instead of CRT
    var key: PrivateKey? = null
    if (firstPrimeFactor != null && secondPrimeFactor != null && firstFactorCRTExponent != null && secondFactorCRTExponent != null && firstCRTCoefficient != null) {
        if (!otherPrimesInfo.isNullOrEmpty()) {
            key = keyFactory.tryPrivateKeySpec(RSAMultiPrimePrivateCrtKeySpec(modulus, publicExponent, privateExponent, firstPrimeFactor, secondPrimeFactor, firstFactorCRTExponent, secondFactorCRTExponent, firstCRTCoefficient, otherPrimesInfo))
        }
        if (key == null) {
            key = keyFactory.tryPrivateKeySpec(RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, firstPrimeFactor, secondPrimeFactor, firstFactorCRTExponent, secondFactorCRTExponent, firstCRTCoefficient))
        }
    }
    if (key == null) {
        //run the final fallback directly so we can wrap it's exception
        key = try {
            keyFactory.generatePrivate(RSAPrivateKeySpec(modulus, privateExponent))
        } catch (e: InvalidKeySpecException) {
            throw UnsupportedKeyException(e.message ?: "InvalidKeySpecException", e)
        }
    }
    return key as RSAPrivateKey
}

private fun ByteArray.toUnsigned(): ByteArray {
    return if (this[0].toInt() == 0) {
        // Strip the sign digit
        val newArray = ByteArray(this.size - 1)
        System.arraycopy(this, 1, newArray, 0, this.size - 1)
        newArray
    } else {
        this
    }
}

private fun BigInteger.toBytesUnsigned(): ByteArray = this.toByteArray().toUnsigned()

/** Wrapper for the Crt key interfaces as multi-prime doesn't extend from RSAPrivateCrtKey */
private interface CrtAdapter {
    val primeP: BigInteger
    val primeExponentP: BigInteger
    val primeQ: BigInteger
    val primeExponentQ: BigInteger
    val crtCoefficient: BigInteger
    val publicExponent: BigInteger
}

private class RSAPrivateCrtKeyAdapter(private val key: RSAPrivateCrtKey): CrtAdapter {
    override val primeP: BigInteger
        get() = key.primeP
    override val primeExponentP: BigInteger
        get() = key.primeExponentP
    override val primeQ: BigInteger
        get() = key.primeQ
    override val primeExponentQ: BigInteger
        get() = key.primeExponentQ
    override val crtCoefficient: BigInteger
        get() = key.crtCoefficient
    override val publicExponent: BigInteger
        get() = key.publicExponent
}

private class RSAMultiPrimePrivateCrtKeyAdapter(private val key: RSAMultiPrimePrivateCrtKey): CrtAdapter {
    override val primeP: BigInteger
        get() = key.primeP
    override val primeExponentP: BigInteger
        get() = key.primeExponentP
    override val primeQ: BigInteger
        get() = key.primeQ
    override val primeExponentQ: BigInteger
        get() = key.primeExponentQ
    override val crtCoefficient: BigInteger
        get() = key.crtCoefficient
    override val publicExponent: BigInteger
        get() = key.publicExponent
}

@Suppress("FunctionName")
@Contract("null, null -> fail")
public fun JsonWebKey.Companion.RSA(publicKey: RSAPublicKey? = null, privateKey: RSAPrivateKey? = null, keyId: String? = null): JsonWebKey.RSA {
    if (publicKey == null && privateKey == null){
        throw IllegalArgumentException("One of private or public keys must be supplied")
    }
    val modulus = when (publicKey) {
        null -> privateKey!!.modulus!!
        else -> publicKey.modulus!!
    }
    val privateCrt: CrtAdapter? = when (privateKey) {
        is RSAPrivateCrtKey -> RSAPrivateCrtKeyAdapter(privateKey)
        is RSAMultiPrimePrivateCrtKey -> RSAMultiPrimePrivateCrtKeyAdapter(privateKey)
        else ->  null
    }
    val publicExponent = when (publicKey) {
        null -> privateCrt?.publicExponent ?: error("Can't get public exponent from private key")
        else -> publicKey.publicExponent
    }
    return JsonWebKey.RSA(
        keyId = keyId,
        modulus = modulus.toBytesUnsigned(),
        exponent = publicExponent?.toBytesUnsigned(),
        privateExponent = privateKey?.privateExponent?.toBytesUnsigned(),
        firstPrimeFactor = privateCrt?.primeP?.toBytesUnsigned(),
        firstFactorCRTExponent = privateCrt?.primeExponentP?.toBytesUnsigned(),
        secondPrimeFactor = privateCrt?.primeQ?.toBytesUnsigned(),
        secondFactorCRTExponent = privateCrt?.primeExponentQ?.toBytesUnsigned(),
        firstCRTCoefficient = privateCrt?.crtCoefficient?.toBytesUnsigned(),
        otherPrimesInfo = when (privateKey) {
            is RSAMultiPrimePrivateCrtKey -> {
                privateKey.otherPrimeInfo.map {
                    JsonWebKey.RSA.OtherPrimeInfo(it.prime.toBytesUnsigned(), it.exponent.toBytesUnsigned(), it.crtCoefficient.toBytesUnsigned())
                }
            }
            else -> null
        }
    )
}
