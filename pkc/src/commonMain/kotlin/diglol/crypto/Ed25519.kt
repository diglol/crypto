package diglol.crypto

import diglol.crypto.random.nextBytes

// https://datatracker.ietf.org/doc/html/rfc8032
expect object Ed25519 : Dsa {
  override suspend fun generateKeyPair(): KeyPair
  override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair

  override suspend fun sign(privateKey: ByteArray, data: ByteArray): ByteArray
  suspend fun sign(keyPair: KeyPair, data: ByteArray): ByteArray
  override suspend fun verify(signature: ByteArray, publicKey: ByteArray, data: ByteArray): Boolean
}

private const val KEY_SIZE = 32
private const val SIGN_SIZE = KEY_SIZE * 2

internal fun generateEd25519PrivateKey(): ByteArray = nextBytes(KEY_SIZE)

internal fun checkEd25519PrivateKey(privateKey: ByteArray) {
  if (privateKey.size != KEY_SIZE) {
    throw Error("Invalid privateKey, must be $KEY_SIZE bytes")
  }
}

internal fun checkEd25519PublicKey(publicKey: ByteArray) {
  if (publicKey.size != KEY_SIZE) {
    throw Error("Invalid publicKey, must be $KEY_SIZE bytes")
  }
}

internal fun checkEd25519Signature(signature: ByteArray) {
  if (signature.size != SIGN_SIZE) {
    throw Error("Invalid sign, must be $SIGN_SIZE bytes")
  }
}
