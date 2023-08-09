package diglol.crypto

// https://datatracker.ietf.org/doc/html/rfc2104
expect class Hmac(type: Type, key: ByteArray) : Mac {
  internal val type: Type
  internal val key: ByteArray

  enum class Type {
    SHA1,
    SHA256,
    SHA384,
    SHA512;

    fun size(): Int
  }

  override fun size(): Int

  override suspend fun compute(data: ByteArray, macSize: Int): ByteArray
  override suspend fun verify(mac: ByteArray, data: ByteArray): Boolean
}

internal inline fun Hmac.Type.commonSize(): Int = when (this) {
  Hmac.Type.SHA1 -> 20
  Hmac.Type.SHA256 -> 32
  Hmac.Type.SHA384 -> 48
  Hmac.Type.SHA512 -> 64
  else -> TODO("https://youtrack.jetbrains.com/issue/KT-43875")
}
