package diglol.crypto

interface Aead {
  enum class Alg {
    AES_GCM,
    XCHACHA20_POLY1305,
    ENCRYPT_THEN_MAC
  }

  suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray
  suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray
}
