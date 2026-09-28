package org.decentwallet.wallet.android

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.MessageDigest
import java.security.SecureRandom

internal object AndroidIdentityCrypto {
    const val KEY_BYTES = 32

    fun generateSeed(random: SecureRandom = SecureRandom()): ByteArray {
        val seed = ByteArray(KEY_BYTES)
        try {
            random.nextBytes(seed)
            return seed
        } catch (_: Exception) {
            seed.fill(0)
            throw WalletKeyGenerationException()
        }
    }

    fun publicKeyFromSeed(seed: ByteArray): ByteArray {
        if (seed.size != KEY_BYTES) throw WalletInvalidContainerException()
        return try {
            Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
        } catch (_: Exception) {
            throw WalletInvalidContainerException()
        }
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        if (seed.size != KEY_BYTES) throw WalletSigningException()
        return try {
            val signer = Ed25519Signer()
            signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
            signer.update(message, 0, message.size)
            signer.generateSignature()
        } catch (_: Exception) {
            throw WalletSigningException()
        }
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != KEY_BYTES || signature.size != SIGNATURE_BYTES) return false
        return try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signature)
        } catch (_: Exception) {
            false
        }
    }

    fun sha256(bytes: ByteArray): ByteArray = try {
        MessageDigest.getInstance("SHA-256").digest(bytes)
    } catch (_: Exception) {
        throw WalletInvalidIdentityStateException()
    }

    fun equalPublicKeys(left: ByteArray, right: ByteArray): Boolean =
        MessageDigest.isEqual(left, right)

    const val SIGNATURE_BYTES = 64
}
