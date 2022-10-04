package diglol.crypto

import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.convert
import kotlinx.cinterop.refTo
import platform.CoreCrypto.CCKeyDerivationPBKDF
import platform.CoreCrypto.kCCPBKDF2
import platform.CoreCrypto.kCCPRFHmacAlgSHA1
import platform.CoreCrypto.kCCPRFHmacAlgSHA256
import platform.CoreCrypto.kCCPRFHmacAlgSHA384
import platform.CoreCrypto.kCCPRFHmacAlgSHA512
import platform.posix.uint8_tVar

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
    val passwordString = password.decodeToString()
    val alg = when (hmacType) {
      Hmac.Type.SHA1 -> kCCPRFHmacAlgSHA1
      Hmac.Type.SHA256 -> kCCPRFHmacAlgSHA256
      Hmac.Type.SHA384 -> kCCPRFHmacAlgSHA384
      Hmac.Type.SHA512 -> kCCPRFHmacAlgSHA512
    }
    val result = ByteArray(keySize)
    @Suppress("UNCHECKED_CAST", "OPT_IN_USAGE")
    CCKeyDerivationPBKDF(
      kCCPBKDF2,
      passwordString,
      passwordString.length.convert(),
      salt.refTo(0) as CValuesRef<uint8_tVar>,
      salt.size.convert(),
      alg,
      iterations.toUInt(),
      result.refTo(0) as CValuesRef<uint8_tVar>,
      result.size.convert()
    )
    return result
  }
}
