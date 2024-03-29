package diglol.crypto

import diglol.crypto.internal.refToOrElse
import diglol.crypto.internal.selfOrCopyOf
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.convert
import kotlinx.cinterop.refTo
import platform.CoreCrypto.CCHmac
import platform.CoreCrypto.kCCHmacAlgSHA1
import platform.CoreCrypto.kCCHmacAlgSHA256
import platform.CoreCrypto.kCCHmacAlgSHA384
import platform.CoreCrypto.kCCHmacAlgSHA512

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

    fun typeName(): UInt = when (this) {
      SHA1 -> kCCHmacAlgSHA1
      SHA256 -> kCCHmacAlgSHA256
      SHA384 -> kCCHmacAlgSHA384
      SHA512 -> kCCHmacAlgSHA512
    }
  }

  actual override fun size(): Int = type.size()

  @OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
  actual override suspend fun compute(data: ByteArray, macSize: Int): ByteArray {
    checkMacSize(macSize)
    val mac = ByteArray(size())
    CCHmac(
      type.typeName(),
      key.refTo(0),
      key.size.convert(),
      data.refToOrElse(0),
      data.size.convert(),
      mac.refTo(0)
    )
    return mac.selfOrCopyOf(macSize)
  }

  actual override suspend fun verify(mac: ByteArray, data: ByteArray): Boolean =
    commonVerify(mac, data)
}
