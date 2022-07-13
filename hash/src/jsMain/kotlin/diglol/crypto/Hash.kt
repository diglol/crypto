package diglol.crypto

import diglol.crypto.internal.subtle
import kotlin.js.Promise
import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array

actual class Hash actual constructor(
  internal actual val type: Type
) {
  private val alg = js("{}")

  init {
    alg["name"] = type.type()
  }

  actual enum class Type {
    SHA1,
    SHA256,
    SHA384,
    SHA512;

    fun type(): String = when (this) {
      SHA1 -> "SHA-1"
      SHA256 -> "SHA-256"
      SHA384 -> "SHA-384"
      SHA512 -> "SHA-512"
    }
  }

  actual suspend fun hash(data: ByteArray): ByteArray {
    val hash = (subtle.digest(alg, data) as Promise<ArrayBuffer>).await()
    return Int8Array(hash).unsafeCast<ByteArray>()
  }
}
