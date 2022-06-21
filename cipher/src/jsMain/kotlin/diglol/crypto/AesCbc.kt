package diglol.crypto

import diglol.crypto.random.nextBytes
import kotlin.js.Promise
import kotlinx.browser.window
import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array

// https://datatracker.ietf.org/doc/html/rfc3602
actual class AesCbc actual constructor(
  internal actual val key: ByteArray,
  internal actual val iv: ByteArray?
) : Cipher {
  private val subtle = window.asDynamic().crypto.subtle
  private val alg = js("{'name': 'AES-CBC'}")

  init {
    checkKey()
    checkIv()
  }

  actual override suspend fun encrypt(plaintext: ByteArray): ByteArray {
    checkPlaintext(plaintext)
    val rawKey = (subtle.importKey("raw", key, alg, true, js("['encrypt']"))
      .unsafeCast<Promise<Any>>()).await()
    val realIv = iv ?: nextBytes(IV_SIZE)
    alg["iv"] = realIv
    val ciphertext = (subtle.encrypt(alg, rawKey, plaintext) as Promise<ArrayBuffer>).await()
    return realIv + Int8Array(ciphertext).unsafeCast<ByteArray>()
  }

  actual override suspend fun decrypt(ciphertext: ByteArray): ByteArray {
    checkCiphertext(ciphertext)
    val rawKey = (subtle.importKey("raw", key, alg, true, js("['decrypt']"))
      .unsafeCast<Promise<Any>>()).await()
    alg["iv"] = ciphertext.copyOf(IV_SIZE)
    val rawCiphertext = ciphertext.copyOfRange(IV_SIZE, ciphertext.size)
    val plaintext = (subtle.decrypt(alg, rawKey, rawCiphertext) as Promise<ArrayBuffer>).await()
    return Int8Array(plaintext).unsafeCast<ByteArray>()
  }

  actual companion object {
    actual val IV_SIZE: Int = AES_CBC_IV_SIZE
  }
}
