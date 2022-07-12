package diglol.crypto

import diglol.crypto.internal.selfOrCopyOf
import diglol.crypto.internal.subtle
import kotlin.js.Promise
import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array

// https://datatracker.ietf.org/doc/html/rfc2104
actual class Hmac actual constructor(
  internal actual val type: Type,
  internal actual val key: ByteArray
) : Mac {
  actual enum class Type {
    SHA1,
    SHA256,
    SHA384,
    SHA512;

    actual fun size(): Int = commonSize()

    fun type(): String = when (this) {
      SHA1 -> "SHA-1"
      SHA256 -> "SHA-256"
      SHA384 -> "SHA-384"
      SHA512 -> "SHA-512"
    }
  }

  private val alg = js("{'name': 'HMAC', 'hash': {}}")

  init {
    checkParams()
    alg["hash"]["name"] = type.type()
  }

  actual override fun size(): Int = type.size()

  actual override suspend fun compute(data: ByteArray, macSize: Int): ByteArray {
    checkMacSize(macSize)
    val realKey =
      ((subtle.importKey("raw", key, alg, true, js("['sign']"))) as Promise<ByteArray>).await()
    val signature = (subtle.sign(alg, realKey, data) as Promise<ArrayBuffer>).await()
    return Int8Array(signature).unsafeCast<ByteArray>().selfOrCopyOf(macSize)
  }

  actual override suspend fun verify(mac: ByteArray, data: ByteArray): Boolean =
    commonVerify(mac, data)
}
