package diglol.crypto

import java.security.MessageDigest

actual class Hash actual constructor(internal actual val type: Type) {
  actual enum class Type {
    SHA1,
    SHA256,
    SHA384,
    SHA512;

    fun algName(): String {
      return when (this) {
        SHA1 -> "SHA-1"
        SHA256 -> "SHA-256"
        SHA384 -> "SHA-384"
        SHA512 -> "SHA-512"
      }
    }
  }

  actual suspend fun hash(data: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance(type.algName())
    digest.update(data)
    return digest.digest()
  }
}
