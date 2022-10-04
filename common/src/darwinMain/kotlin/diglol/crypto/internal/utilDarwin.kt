package diglol.crypto.internal

import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.dataWithBytesNoCopy
import platform.posix.memcpy

fun COpaquePointer?.toByteArray(size: Int): ByteArray {
  return if (this != null && size != 0) {
    ByteArray(size).apply {
      usePinned {
        memcpy(it.addressOf(0), this@toByteArray, size.convert())
      }
    }
  } else {
    emptyBytes
  }
}

fun NSData.toByteArray(): ByteArray = bytes.toByteArray(length.convert())

fun ByteArray.toNSData(freeWhenDone: Boolean = false): NSData = this.usePinned {
  val bytesPointer = when {
    isNotEmpty() -> it.addressOf(0)
    else -> null
  }
  NSData.dataWithBytesNoCopy(
    bytes = bytesPointer,
    length = size.convert(),
    freeWhenDone = freeWhenDone
  )
}

