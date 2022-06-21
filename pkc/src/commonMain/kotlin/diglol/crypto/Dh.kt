package diglol.crypto

interface Dh {
  enum class Alg {
    X25519,
    // TODO X448
  }

  suspend fun generateKeyPair(): KeyPair
  suspend fun generateKeyPair(privateKey: ByteArray): KeyPair

  suspend fun compute(privateKey: ByteArray, peersPublicKey: ByteArray): ByteArray
}
