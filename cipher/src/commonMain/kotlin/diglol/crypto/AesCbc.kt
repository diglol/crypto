package diglol.crypto

import diglol.crypto.AesCbc.Companion.IV_SIZE

// https://datatracker.ietf.org/doc/html/rfc3602
expect class AesCbc(key: ByteArray, iv: ByteArray? = null) : Cipher {
  internal val key: ByteArray
  internal val iv: ByteArray?

  override suspend fun encrypt(plaintext: ByteArray): ByteArray
  override suspend fun decrypt(ciphertext: ByteArray): ByteArray

  companion object {
    val IV_SIZE: Int
  }
}

internal const val AES_CBC_IV_SIZE = 16

internal fun AesCbc.checkKey() {
  if (key.size != 16 && key.size != 32) {
    throw Error("Invalid AES key size, expected 16 or 32, but got ${key.size}")
  }
}

internal fun AesCbc.checkIv() {
  if (iv != null && iv.size != IV_SIZE) {
    throw Error("Iv must have 16 bytes")
  }
}

internal fun AesCbc.checkPlaintext(plaintext: ByteArray) {
  if (plaintext.size > Int.MAX_VALUE - IV_SIZE) {
    throw Error("Plaintext size can not exceed ${Int.MAX_VALUE - IV_SIZE}")
  }
}

internal fun AesCbc.checkCiphertext(ciphertext: ByteArray) {
  if (ciphertext.size < IV_SIZE) {
    throw Error("Ciphertext too shoot")
  }
}
