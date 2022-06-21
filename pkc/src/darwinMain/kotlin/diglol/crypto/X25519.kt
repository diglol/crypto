package diglol.crypto

import cocoapods.Curve25519.X25519 as DarwinX25519
import diglol.crypto.internal.toNSData
import diglol.crypto.internal.toByteArray

// https://datatracker.ietf.org/doc/html/rfc7748
actual object X25519 : Dh {
  actual override suspend fun generateKeyPair(): KeyPair =
    generateKeyPair(generateX25519PrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkX25519PrivateKey(privateKey)
    return DarwinX25519.generateKeyPairWithPrivateKey(privateKey.toNSData())!!.toKeyPair()
  }

  actual override suspend fun compute(privateKey: ByteArray, peersPublicKey: ByteArray): ByteArray {
    checkX25519PrivateKey(privateKey)
    checkX25519PublicKey(peersPublicKey)
    val sharedSecret = DarwinX25519.computeSharedSecretWithPrivateKey(
      privateKey.toNSData(),
      peersPublicKey.toNSData()
    )
    return sharedSecret!!.toByteArray()
  }
}
