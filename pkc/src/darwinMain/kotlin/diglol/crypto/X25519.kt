package diglol.crypto

import cocoapods.Curve25519.X25519 as DarwinX25519
import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toNSData

// https://datatracker.ietf.org/doc/html/rfc7748
actual object X25519 : Dh {
  actual val KEY_SIZE: Int = X25519_KEY_SIZE

  actual override suspend fun generateKeyPair(): KeyPair = generateKeyPair(generatePrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkPrivateKey(privateKey)
    return DarwinX25519.generateKeyPairWithPrivateKey(privateKey.toNSData())!!.toKeyPair()
  }

  actual override suspend fun compute(privateKey: ByteArray, peersPublicKey: ByteArray): ByteArray {
    checkPrivateKey(privateKey)
    checkPublicKey(peersPublicKey)
    val sharedSecret = DarwinX25519.computeSharedSecretWithPrivateKey(
      privateKey.toNSData(),
      peersPublicKey.toNSData()
    )
    return sharedSecret!!.toByteArray()
  }
}
