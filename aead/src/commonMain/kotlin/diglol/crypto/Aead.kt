package diglol.crypto

import diglol.crypto.internal.emptyBytes

interface Aead {
  enum class Alg {
    AES_GCM,
    XCHACHA20_POLY1305,
    ENCRYPT_THEN_MAC
  }

  suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray = emptyBytes): ByteArray
  suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray = emptyBytes): ByteArray
}
