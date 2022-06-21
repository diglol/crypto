package diglol.crypto

// https://datatracker.ietf.org/doc/html/rfc4634
expect class Hash(type: Type) {
  internal val type: Type

  enum class Type {
    SHA1,
    SHA256,
    SHA384,
    SHA512
  }

  suspend fun hash(data: ByteArray): ByteArray
}
