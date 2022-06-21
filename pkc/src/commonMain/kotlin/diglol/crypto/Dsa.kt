package diglol.crypto

interface Dsa {
  enum class Alg {
    ED25519,
    // TODO ED448
  }

  suspend fun generateKeyPair(): KeyPair
  suspend fun generateKeyPair(privateKey: ByteArray): KeyPair

  suspend fun sign(privateKey: ByteArray, data: ByteArray): ByteArray
  suspend fun verify(signature: ByteArray, publicKey: ByteArray, data: ByteArray): Boolean
}
