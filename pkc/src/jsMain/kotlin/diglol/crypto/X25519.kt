package diglol.crypto

import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toUint8Array

// https://datatracker.ietf.org/doc/html/rfc7748
actual object X25519 : Dh {
  actual override suspend fun generateKeyPair(): KeyPair =
    generateKeyPair(generateX25519PrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkX25519PrivateKey(privateKey)
    val publicKey = Ed25519Js.curve25519.scalarMultBase(privateKey.toUint8Array()).toByteArray()
    return KeyPair(publicKey, privateKey)
  }

  actual override suspend fun compute(privateKey: ByteArray, peersPublicKey: ByteArray): ByteArray {
    checkX25519PrivateKey(privateKey)
    checkX25519PublicKey(peersPublicKey)
    return Ed25519Js.curve25519.scalarMult(privateKey.toUint8Array(), peersPublicKey.toUint8Array())
      .toByteArray()
  }
}
