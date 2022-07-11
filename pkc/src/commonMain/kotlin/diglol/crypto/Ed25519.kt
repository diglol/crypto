package diglol.crypto

import diglol.crypto.random.nextBytes

// https://datatracker.ietf.org/doc/html/rfc8032
expect object Ed25519 : Dsa {
  val KEY_SIZE: Int
  val SIGN_SIZE: Int

  override suspend fun generateKeyPair(): KeyPair
  override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair

  override suspend fun sign(privateKey: ByteArray, data: ByteArray): ByteArray
  suspend fun sign(keyPair: KeyPair, data: ByteArray): ByteArray
  override suspend fun verify(signature: ByteArray, publicKey: ByteArray, data: ByteArray): Boolean
}

internal const val ED25519_KEY_SIZE = 32
internal const val ED25519_SIGN_SIZE = ED25519_KEY_SIZE * 2

internal fun Ed25519.generatePrivateKey(): ByteArray = nextBytes(KEY_SIZE)

internal fun Ed25519.checkPrivateKey(privateKey: ByteArray) {
  if (privateKey.size != KEY_SIZE) {
    throw Error("Invalid privateKey, must be $KEY_SIZE bytes")
  }
}

internal fun Ed25519.checkPublicKey(publicKey: ByteArray) {
  if (publicKey.size != KEY_SIZE) {
    throw Error("Invalid publicKey, must be $KEY_SIZE bytes")
  }
}

internal fun Ed25519.checkSignature(signature: ByteArray) {
  if (signature.size != SIGN_SIZE) {
    throw Error("Invalid sign, must be $SIGN_SIZE bytes")
  }
}
