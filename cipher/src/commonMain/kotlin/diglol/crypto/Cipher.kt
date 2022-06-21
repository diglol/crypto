package diglol.crypto

interface Cipher {
  enum class Alg {
    AES_CBC,
    XCHACHA20
  }

  suspend fun encrypt(plaintext: ByteArray): ByteArray
  suspend fun decrypt(ciphertext: ByteArray): ByteArray
}
