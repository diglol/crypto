package diglol.crypto

interface Kdf {
  enum class Alg {
    ARGON2,
    PBKDF2
  }

  suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray
}
