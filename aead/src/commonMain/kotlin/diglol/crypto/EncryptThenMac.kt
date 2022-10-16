package diglol.crypto

import diglol.crypto.internal.plusByteArrays
import diglol.crypto.internal.toByteArray
import kotlin.jvm.JvmOverloads

// https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
class EncryptThenMac @JvmOverloads constructor(
  private val cipher: Cipher,
  private val mac: Mac,
  private val macSize: Int = mac.size()
) : Aead {
  override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
    val ciphertext = cipher.encrypt(plaintext)
    val associatedDataSize = 8L * associatedData.size
    // aad || ciphertext || aadSize(Long)
    val data = associatedData.plusByteArrays(ciphertext, associatedDataSize.toByteArray())
    return ciphertext + mac.compute(data, macSize)
  }

  override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
    if (ciphertext.size < macSize) {
      throw Error("Ciphertext too short")
    }
    val rawCiphertextSize = ciphertext.size - macSize
    val rawCiphertext = ciphertext.copyOf(rawCiphertextSize)
    val macValue = ciphertext.copyOfRange(rawCiphertextSize, ciphertext.size)
    val associatedDataSize = 8L * associatedData.size
    val data = associatedData.plusByteArrays(rawCiphertext, associatedDataSize.toByteArray())
    if (!mac.verify(macValue, data)) {
      throw Error("Invalid mac")
    }
    return cipher.decrypt(rawCiphertext)
  }
}
