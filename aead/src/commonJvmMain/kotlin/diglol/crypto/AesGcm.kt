package diglol.crypto

import diglol.crypto.random.nextBytes
import javax.crypto.Cipher as CipherJvm
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// https://datatracker.ietf.org/doc/html/rfc5288
actual class AesGcm actual constructor(
  internal actual val key: ByteArray,
  internal actual val iv: ByteArray?
) : Aead {
  init {
    checkKey()
    checkIv()
  }

  private val keySpec = SecretKeySpec(key, "AES")

  actual override suspend fun encrypt(
    plaintext: ByteArray,
    associatedData: ByteArray
  ): ByteArray {
    checkPlaintext(plaintext)
    try {
      val cipher = localCipher.get()
      val realIv = iv ?: nextBytes(IV_SIZE)
      cipher.init(CipherJvm.ENCRYPT_MODE, keySpec, GCMParameterSpec(8 * TAG_SIZE, realIv))
      if (associatedData.isNotEmpty()) {
        cipher.updateAAD(associatedData)
      }
      return realIv + cipher.doFinal(plaintext)
    } catch (e: Exception) {
      throw Error("Aes gcm encrypt error", e)
    }
  }

  actual override suspend fun decrypt(
    ciphertext: ByteArray,
    associatedData: ByteArray
  ): ByteArray {
    checkCiphertext(ciphertext)
    val iv = ciphertext.copyOf(IV_SIZE)
    val rawCiphertext = ciphertext.copyOfRange(IV_SIZE, ciphertext.size)
    try {
      val cipher = localCipher.get()
      cipher.init(CipherJvm.DECRYPT_MODE, keySpec, GCMParameterSpec(8 * TAG_SIZE, iv))
      if (associatedData.isNotEmpty()) {
        cipher.updateAAD(associatedData)
      }
      return cipher.doFinal(rawCiphertext)
    } catch (e: Exception) {
      throw Error("Aes gcm decrypt error", e)
    }
  }

  actual companion object {
    private val localCipher = object : ThreadLocal<CipherJvm>() {
      override fun initialValue(): CipherJvm {
        return CipherJvm.getInstance("AES/GCM/NoPadding")
      }
    }
    actual val IV_SIZE: Int = AES_GCM_IV_SIZE
    actual val TAG_SIZE: Int = AES_GCM_TAG_SIZE
  }
}
