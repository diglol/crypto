package diglol.crypto.internal

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.refTo
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.dataWithBytesNoCopy
import platform.posix.memcpy

fun COpaquePointer?.toByteArray(size: Int): ByteArray {
  return if (this != null && size != 0) {
    ByteArray(size).apply {
      usePinned {
        @Suppress("OPT_IN_USAGE")
        memcpy(it.addressOf(0), this@toByteArray, size.convert())
      }
    }
  } else {
    emptyBytes
  }
}

@Suppress("OPT_IN_USAGE")
fun NSData.toByteArray(): ByteArray = bytes.toByteArray(length.convert())

fun ByteArray.toNSData(freeWhenDone: Boolean = false): NSData = usePinned {
  val bytesPointer = when {
    isNotEmpty() -> it.addressOf(0)
    else -> null
  }
  @Suppress("OPT_IN_USAGE")
  NSData.dataWithBytesNoCopy(
    bytes = bytesPointer,
    length = size.convert(),
    freeWhenDone = freeWhenDone
  )
}

fun ByteArray.refToOrElse(
  index: Int,
  default: CValuesRef<ByteVar>? = null
): CValuesRef<ByteVar>? = if (isNotEmpty()) refTo(index) else default
