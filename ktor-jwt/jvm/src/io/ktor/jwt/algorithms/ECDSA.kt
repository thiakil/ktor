/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.jwt.algorithms

import io.ktor.jwt.InvalidSignatureException
import io.ktor.jwt.*
import io.ktor.util.*
import io.ktor.utils.io.core.*
import java.math.*
import java.security.*
import java.security.spec.*
import kotlin.math.*
import java.security.spec.ECGenParameterSpec

import java.security.AlgorithmParameters
import java.security.interfaces.*

private val JsonWebKey.EllipticCurve.ecParameterSpec: ECParameterSpec
    get() {
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(
            ECGenParameterSpec(
                when (curve) {
                    "P-256" -> "secp256r1"
                    "P-384" -> "secp384r1"
                    "P-521" -> "secp521r1"
                    else -> throw UnsupportedKeyException("Unknown curve: $curve")
                }
            )
        )
        return parameters.getParameterSpec(ECParameterSpec::class.java)!!
    }

internal fun JsonWebKey.EllipticCurve.toJavaPublic(): ECPublicKey {
    val pubPoint = ECPoint(BigInteger(1, x), BigInteger(1, y))
    val pubSpec = ECPublicKeySpec(pubPoint, ecParameterSpec)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePublic(pubSpec) as ECPublicKey
}

internal fun JsonWebKey.EllipticCurve.toJavaPrivate(): ECPrivateKey {
    val privateSpec = ECPrivateKeySpec(BigInteger(1, eccPrivateKey!!), ecParameterSpec)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePrivate(privateSpec) as ECPrivateKey
}

public data class JavaECKey(val publicKey: ECPublicKey? = null, val privateKey: ECPrivateKey? = null): SigningKey

public sealed class EcdsaBase(override val jwaId: String, shaType: SHAType): JwsAlgorithm {
    /** Size (in bytes) of the R,S integers. Equal to the size of the key */
    private val rsSize: Int = when(shaType) {
        SHAType.SHA256 -> 32
        SHAType.SHA384 -> 48
        SHAType.SHA512 -> 64
    }
    private val javaSigAlg = when(shaType) {
        SHAType.SHA256 -> "SHA256withECDSA"
        SHAType.SHA384 -> "SHA384withECDSA"
        SHAType.SHA512 -> "SHA512withECDSA"
    }

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val publicKey: PublicKey = when(key) {
            is JsonWebKey.EllipticCurve -> key.toJavaPublic()
            is JavaECKey -> key.publicKey!!
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance(javaSigAlg)
        s.initVerify(publicKey)
        s.update(signature.subject.toByteArray(Charsets.UTF_8))
        return s.verify(convertRawSigToDER(signature.signature))
    }

    override fun sign(payload: String, key: SigningKey): String {
        val privateKey: PrivateKey = when(key) {
            is JsonWebKey.EllipticCurve -> key.toJavaPrivate()
            is JavaECKey -> key.privateKey!!
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance(javaSigAlg)
        s.initSign(privateKey, SecureRandom())
        s.update(payload.toByteArray(Charsets.UTF_8))
        return convertDERToRaw(s.sign()).encodeBase64Url()
    }

    /**
     * Converts from raw {R,S} signature format to DER-encoded like Java expects
     */
    private fun convertRawSigToDER(rawSignature: ByteArray): ByteArray {
        if (rawSignature.size != rsSize * 2) {
            throw InvalidSignatureException("Size mismatch for algorithm")
        }

        // Retrieve R and S number's length and padding.
        val rPadding: Int = countPadding(rawSignature, 0, rsSize)
        val sPadding: Int = countPadding(rawSignature, rsSize, rawSignature.size)
        val rLength: Int = rsSize - rPadding
        val sLength: Int = rsSize - sPadding
        val length = 2 + rLength + 2 + sLength
        if (length > 255) {
            throw InvalidSignatureException("Expected compressed length <= 255")
        }

        return buildPacket {
            // DER Structure: http://crypto.stackexchange.com/a/1797
            // Header with signature length info
            writeByte(0x30)
            if (length > 0x7f){
                writeByte(0x81.toByte())
            }
            writeByte((length and 0xff).toByte())

            // Header with "min R" number length
            writeByte(0x02)
            writeByte(rLength.toByte())

            // R number
            if (rPadding < 0) {
                writeByte(0)
                writeFully(src=rawSignature, offset=0, length=rsSize)
            } else {
                writeFully(src = rawSignature, offset = rPadding, length = min(rsSize, rLength))
            }

            // Header with "min S" number length
            writeByte(0x02)
            writeByte(sLength.toByte())

            // S number
            if (sPadding < 0) {
                writeByte(0)
                writeFully(src=rawSignature, offset=rsSize, length=rsSize)
            } else {
                writeFully(src=rawSignature, offset=rsSize+sPadding, length=min(rsSize, sLength))
            }

        }.readBytes()
    }

    private fun convertDERToRaw(derSignature: ByteArray): ByteArray {
        // DER Structure: http://crypto.stackexchange.com/a/1797
        val derEncoded = derSignature[0] == 0x30.toByte() && derSignature.size != rsSize * 2
        if (!derEncoded) {
            throw InvalidSignatureException("Invalid DER signature format.")
        }

        val joseSignature = ByteArray(rsSize * 2)

        //Skip 0x30
        var offset = 1
        if (derSignature[1] == 0x81.toByte()) {
            //Skip sign
            offset++
        }

        //Convert to unsigned. Should match DER length - offset
        val encodedLength: Int = derSignature[offset++].toInt() and 0xff
        if (encodedLength != derSignature.size - offset) {
            throw InvalidSignatureException("Invalid DER signature format.")
        }

        //Skip 0x02
        offset++

        //Obtain R number length (Includes padding) and skip it
        val rLength = derSignature[offset++].toInt()
        if (rLength > rsSize + 1) {
            throw InvalidSignatureException("Invalid DER signature format.")
        }
        val rPadding: Int = rsSize - rLength
        //Retrieve R number
        System.arraycopy(
            derSignature,
            offset + max(-rPadding, 0),
            joseSignature,
            max(rPadding, 0),
            rLength + min(rPadding, 0)
        )

        //Skip R number and 0x02
        offset += rLength + 1

        //Obtain S number length. (Includes padding)
        val sLength = derSignature[offset++].toInt()
        if (sLength > rsSize + 1) {
            throw InvalidSignatureException("Invalid DER signature format.")
        }
        val sPadding: Int = rsSize - sLength
        //Retrieve R number
        System.arraycopy(
            derSignature,
            offset + max(-sPadding, 0),
            joseSignature,
            rsSize + max(sPadding, 0),
            sLength + min(sPadding, 0)
        )

        return joseSignature
    }

    private fun countPadding(bytes: ByteArray, fromIndex: Int, toIndex: Int): Int {
        var padding = 0
        while (fromIndex + padding < toIndex && bytes[fromIndex + padding] == 0.toByte()) {
            padding++
        }
        return if (bytes[fromIndex + padding].toInt() and 0xff > 0x7f) padding - 1 else padding
    }
}

public object ES256: EcdsaBase("ES256", SHAType.SHA256)
public object ES384: EcdsaBase("ES384", SHAType.SHA384)
public object ES512: EcdsaBase("ES512", SHAType.SHA512)
