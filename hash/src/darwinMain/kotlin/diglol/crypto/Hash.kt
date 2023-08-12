package diglol.crypto

import diglol.crypto.internal.refToOrElse
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.convert
import kotlinx.cinterop.refTo
import platform.CoreCrypto.CC_LONG
import platform.CoreCrypto.CC_SHA1
import platform.CoreCrypto.CC_SHA1_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA384
import platform.CoreCrypto.CC_SHA384_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA512
import platform.CoreCrypto.CC_SHA512_DIGEST_LENGTH

actual class Hash actual constructor(
  internal actual val type: Type
) {
  actual enum class Type {
    SHA1,
    SHA256,
    SHA384,
    SHA512
  }

  @Suppress("UNCHECKED_CAST")
  @OptIn(ExperimentalForeignApi::class)
  actual suspend fun hash(data: ByteArray): ByteArray {
    val shaFun: (data: CValuesRef<*>?, len: CC_LONG, md: CValuesRef<UByteVar>?) -> CPointer<UByteVar>?
    val shaLen: Int
    when (type) {
      Type.SHA1 -> {
        shaFun = ::CC_SHA1
        shaLen = CC_SHA1_DIGEST_LENGTH
      }

      Type.SHA256 -> {
        shaFun = ::CC_SHA256
        shaLen = CC_SHA256_DIGEST_LENGTH
      }

      Type.SHA384 -> {
        shaFun = ::CC_SHA384
        shaLen = CC_SHA384_DIGEST_LENGTH
      }

      Type.SHA512 -> {
        shaFun = ::CC_SHA512
        shaLen = CC_SHA512_DIGEST_LENGTH
      }
    }
    val result = ByteArray(shaLen)
    shaFun(data.refToOrElse(0), data.size.convert(), result.refTo(0) as CValuesRef<UByteVar>)
    return result
  }
}
