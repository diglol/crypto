package diglol.crypto

import diglol.crypto.random.nextBytes
import kotlin.js.Promise
import kotlinx.browser.window
import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array

// https://datatracker.ietf.org/doc/html/rfc5288
actual class AesGcm actual constructor(
  internal actual val key: ByteArray,
  internal actual val iv: ByteArray?
) : Aead {
  private val subtle = window.asDynamic().crypto.subtle
  private val alg = js("{'name': 'AES-GCM'}")

  init {
    checkKey()
    checkIv()
  }

  actual override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
    checkPlaintext(plaintext)
    val rawKey = (subtle.importKey("raw", key, alg, true, js("['encrypt']"))
      .unsafeCast<Promise<Any>>()).await()
    if (associatedData.isNotEmpty()) {
      alg["additionalData"] = associatedData
    }
    val realIv = iv ?: nextBytes(IV_SIZE)
    alg["iv"] = realIv
    alg["tagLength"] = 8 * TAG_SIZE
    val cipherData = (subtle.encrypt(alg, rawKey, plaintext) as Promise<ArrayBuffer>).await()
    return realIv + Int8Array(cipherData).unsafeCast<ByteArray>()
  }

  actual override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
    checkCiphertext(ciphertext)
    val iv = ciphertext.copyOf(IV_SIZE)
    val rawCiphertext = ciphertext.copyOfRange(IV_SIZE, ciphertext.size)
    val rawKey = (subtle.importKey("raw", key, alg, true, js("['decrypt']"))
      .unsafeCast<Promise<Any>>()).await()
    if (associatedData.isNotEmpty()) {
      alg["additionalData"] = associatedData
    }
    alg["iv"] = iv
    alg["tagLength"] = 8 * TAG_SIZE
    val cipherData = (subtle.decrypt(alg, rawKey, rawCiphertext) as Promise<ArrayBuffer>).await()
    return Int8Array(cipherData).unsafeCast<ByteArray>()
  }

  actual companion object {
    actual val IV_SIZE: Int = AES_GCM_IV_SIZE
    actual val TAG_SIZE: Int = AES_GCM_TAG_SIZE
  }
}
