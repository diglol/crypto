package diglol.crypto

import diglol.crypto.internal.selfOrCopyOf
import javax.crypto.Mac as MacJvm
import javax.crypto.spec.SecretKeySpec

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

    fun typeName(): String = when (this) {
      SHA1 -> "HmacSHA1"
      SHA256 -> "HmacSHA256"
      SHA384 -> "HmacSHA384"
      SHA512 -> "HmacSHA512"
    }
  }

  private val hmac = MacJvm.getInstance(type.typeName())

  init {
    hmac.init(SecretKeySpec(key, type.typeName()))
  }

  actual override fun size(): Int = type.size()

  @JvmOverloads
  actual override suspend fun compute(data: ByteArray, macSize: Int): ByteArray {
    checkMacSize(macSize)
    hmac.update(data)
    return hmac.doFinal().selfOrCopyOf(macSize)
  }

  actual override suspend fun verify(mac: ByteArray, data: ByteArray): Boolean = commonVerify(
    mac, data
  )
}
