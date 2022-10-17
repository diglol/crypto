package diglol.crypto

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

// https://datatracker.ietf.org/doc/html/rfc6070
actual class Pbkdf2 @JvmOverloads actual constructor(
  internal actual val hmacType: Hmac.Type,
  internal actual val iterations: Int,
  internal actual val keySize: Int
) : Kdf {
  init {
    checkParams()
  }

  private val algName = when (hmacType) {
    Hmac.Type.SHA1 -> "PBKDF2WithHmacSHA1"
    Hmac.Type.SHA256 -> "PBKDF2WithHmacSHA256"
    Hmac.Type.SHA384 -> "PBKDF2WithHmacSHA384"
    Hmac.Type.SHA512 -> "PBKDF2WithHmacSHA512"
  }

  private val kdf = SecretKeyFactory.getInstance(algName)

  actual override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray {
    checkPbkdf2Salt(salt)
    val keySpec = PBEKeySpec(String(password).toCharArray(), salt, iterations, keySize * 8)
    return kdf.generateSecret(keySpec).encoded
  }
}
