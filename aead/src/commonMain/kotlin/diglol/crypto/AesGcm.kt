package diglol.crypto

import diglol.crypto.AesGcm.Companion.IV_SIZE
import diglol.crypto.AesGcm.Companion.TAG_SIZE

// https://datatracker.ietf.org/doc/html/rfc5288
expect class AesGcm(key: ByteArray, iv: ByteArray? = null) : Aead {
  internal val key: ByteArray
  internal val iv: ByteArray?

  override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray
  override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray

  companion object {
    val IV_SIZE: Int
    val TAG_SIZE: Int
  }
}

internal const val AES_GCM_IV_SIZE = 12
internal const val AES_GCM_TAG_SIZE = 16

internal fun AesGcm.checkKey() {
  if (key.size != 16 && key.size != 32) {
    throw Error("Invalid AES key size, expected 16 or 32, but got ${key.size}")
  }
}

internal fun AesGcm.checkIv() {
  if (iv != null && iv.size != IV_SIZE) {
    throw Error("Iv must have 12 bytes")
  }
}

internal fun AesGcm.checkPlaintext(plaintext: ByteArray) {
  if (plaintext.size > Int.MAX_VALUE - IV_SIZE - TAG_SIZE) {
    throw Error("Plaintext too long")
  }
}

internal fun AesGcm.checkCiphertext(ciphertext: ByteArray) {
  if (ciphertext.size < IV_SIZE + TAG_SIZE) {
    throw Error("Ciphertext too shoot")
  }
}
