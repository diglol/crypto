package diglol.crypto

import kotlin.random.Random.Default.nextBytes

// https://datatracker.ietf.org/doc/html/rfc7748
expect object X25519 : Dh {
  val KEY_SIZE: Int

  override suspend fun generateKeyPair(): KeyPair
  override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair

  override suspend fun compute(privateKey: ByteArray, peersPublicKey: ByteArray): ByteArray
}

internal const val X25519_KEY_SIZE = 32

internal fun X25519.generatePrivateKey(): ByteArray {
  val privateKey = nextBytes(KEY_SIZE)
  privateKey[0] = (privateKey[0].toInt() and 248).toByte()
  privateKey[31] = (privateKey[31].toInt() and 127).toByte()
  privateKey[31] = ((privateKey[31].toInt()) or 64).toByte()
  return nextBytes(KEY_SIZE)
}

internal fun X25519.checkPrivateKey(privateKey: ByteArray) {
  if (privateKey.size != KEY_SIZE) {
    throw Error("Private key must have 32 bytes.");
  }
}

internal fun X25519.checkPublicKey(publicKey: ByteArray) {
  if (publicKey.size != KEY_SIZE) {
    throw Error("PublicKey key must have 32 bytes.");
  }
}
