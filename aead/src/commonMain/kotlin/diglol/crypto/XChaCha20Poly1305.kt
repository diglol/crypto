package diglol.crypto

import diglol.crypto.Poly1305.Companion.MAC_KEY_SIZE
import diglol.crypto.Poly1305.Companion.MAC_TAG_SIZE
import diglol.crypto.XChaCha20.Companion.NONCE_SIZE
import diglol.crypto.internal.plusByteArrays
import diglol.crypto.internal.toByteArray
import kotlin.jvm.JvmOverloads

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
// https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/subtle/ChaCha20Poly1305Base.java
class XChaCha20Poly1305 @JvmOverloads constructor(
  key: ByteArray,
  private val none: ByteArray? = null
) : Aead {
  private val chacha20 = XChaCha20(key, none, 1)
  private val macKeyChaCha20 = XChaCha20(key, none, 0)

  override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
    if (plaintext.size > Int.MAX_VALUE - NONCE_SIZE - MAC_KEY_SIZE) {
      throw Error("Plaintext too long")
    }
    val ciphertext = chacha20.encrypt(plaintext)
    val realNone = none ?: ciphertext.copyOf(NONCE_SIZE)
    val macKey = macKeyChaCha20.chacha20Block(realNone, 0).copyOf(MAC_KEY_SIZE)
    val rawCiphertext = ciphertext.copyOfRange(NONCE_SIZE, ciphertext.size)
    val mac = Poly1305(macKey).compute(macData(associatedData, rawCiphertext))
    return ciphertext + mac
  }

  override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
    if (ciphertext.size < NONCE_SIZE + MAC_TAG_SIZE) {
      throw Error("Ciphertext too shoot")
    }
    val nonce = ciphertext.copyOf(NONCE_SIZE)
    val rawCiphertextPosition = ciphertext.size - MAC_TAG_SIZE
    val rawCiphertext = ciphertext.copyOfRange(NONCE_SIZE, rawCiphertextPosition)
    val macKey = macKeyChaCha20.chacha20Block(nonce, 0).copyOf(MAC_KEY_SIZE)
    val mac = ciphertext.copyOfRange(rawCiphertextPosition, ciphertext.size)
    if (!Poly1305(macKey).verify(mac, macData(associatedData, rawCiphertext))) {
      throw Error("Invalid mac")
    }
    return chacha20.decrypt(ciphertext.copyOf(rawCiphertextPosition))
  }

  /** Prepares the input to MAC, following RFC 8439, section 2.8. */
  private fun macData(associatedData: ByteArray, ciphertext: ByteArray): ByteArray {
    val associatedDataSize = associatedData.size
    val associatedDataRem = associatedDataSize % 16
    val associatedDataPaddedLen = if (associatedDataRem == 0) 0 else 16 - associatedDataRem
    val ciphertextSize = ciphertext.size
    val ciphertextRem = ciphertextSize % 16
    val ciphertextPaddedLen = if (ciphertextRem == 0) 0 else 16 - ciphertextRem
    return associatedData.plusByteArrays(
      ByteArray(associatedDataPaddedLen),
      ciphertext,
      ByteArray(ciphertextPaddedLen),
      associatedDataSize.toLong().toByteArray(false),
      ciphertextSize.toLong().toByteArray(false)
    )
  }
}
