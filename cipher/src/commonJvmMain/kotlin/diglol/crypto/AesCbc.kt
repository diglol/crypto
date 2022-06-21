package diglol.crypto

import diglol.crypto.random.nextBytes
import javax.crypto.Cipher as CipherJvm
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// https://datatracker.ietf.org/doc/html/rfc3602
actual class AesCbc actual constructor(
  internal actual val key: ByteArray,
  internal actual val iv: ByteArray?
) : Cipher {
  init {
    checkKey()
    checkIv()
  }

  private val keySpec = SecretKeySpec(key, "AES")

  actual override suspend fun encrypt(plaintext: ByteArray): ByteArray {
    checkPlaintext(plaintext)
    try {
      val cipher = localCipher.get()
      val realIv = iv ?: nextBytes(IV_SIZE)
      cipher.init(CipherJvm.ENCRYPT_MODE, keySpec, IvParameterSpec(realIv))
      return realIv + cipher.doFinal(plaintext)
    } catch (e: Exception) {
      throw Error("Aes cbc encrypt error", e)
    }
  }

  actual override suspend fun decrypt(ciphertext: ByteArray): ByteArray {
    checkCiphertext(ciphertext)
    val iv = ciphertext.copyOf(IV_SIZE)
    val rawCiphertext = ciphertext.copyOfRange(IV_SIZE, ciphertext.size)
    try {
      val cipher = localCipher.get()
      cipher.init(CipherJvm.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
      return cipher.doFinal(rawCiphertext)
    } catch (e: Exception) {
      throw Error("Aes cbc decrypt error", e)
    }
  }

  actual companion object {
    private val localCipher = object : ThreadLocal<CipherJvm>() {
      override fun initialValue(): CipherJvm {
        return CipherJvm.getInstance("AES/CBC/PKCS5Padding")
      }
    }
    actual val IV_SIZE: Int = AES_CBC_IV_SIZE
  }
}
