package diglol.crypto

import diglol.crypto.internal.subtle
import kotlin.js.Promise
import kotlinx.browser.window
import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array

// https://datatracker.ietf.org/doc/html/rfc6070
actual class Pbkdf2 actual constructor(
  internal actual val hmacType: Hmac.Type,
  internal actual val iterations: Int,
  internal actual val keySize: Int
) : Kdf {
  init {
    checkParams()
  }

  actual override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray {
    checkPbkdf2Salt(salt)
    val alg = js("{'name': 'PBKDF2', 'hash': {}}")
    alg["salt"] = salt
    alg["iterations"] = iterations
    alg["hash"]["name"] = hmacType.type()
    val rawKey = ((subtle.importKey(
      "raw", password, alg, false, js("['deriveBits']")
    )) as Promise<ByteArray>).await()
    val keyBits = (subtle.deriveBits(alg, rawKey, 8 * keySize) as Promise<ArrayBuffer>).await()
    return Int8Array(keyBits).unsafeCast<ByteArray>()
  }
}
