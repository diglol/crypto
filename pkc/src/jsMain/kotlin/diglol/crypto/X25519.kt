package diglol.crypto

import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toUint8Array

// https://datatracker.ietf.org/doc/html/rfc7748
actual object X25519 : Dh {
  actual val KEY_SIZE: Int = X25519_KEY_SIZE

  actual override suspend fun generateKeyPair(): KeyPair =
    generateKeyPair(generatePrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkPrivateKey(privateKey)
    val publicKey = Ed25519Js.curve25519.scalarMultBase(privateKey.toUint8Array()).toByteArray()
    return KeyPair(publicKey, privateKey)
  }

  actual override suspend fun compute(privateKey: ByteArray, peersPublicKey: ByteArray): ByteArray {
    checkPrivateKey(privateKey)
    checkPublicKey(peersPublicKey)
    return Ed25519Js.curve25519.scalarMult(privateKey.toUint8Array(), peersPublicKey.toUint8Array())
      .toByteArray()
  }
}
