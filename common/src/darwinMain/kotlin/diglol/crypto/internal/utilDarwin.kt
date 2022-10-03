package diglol.crypto.internal

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.dataWithBytesNoCopy
import platform.posix.memcpy

inline fun NSData.toByteArray(): ByteArray {
  val size = length.toInt()
  return if (size != 0) {
    ByteArray(size).apply {
      usePinned {
        memcpy(it.addressOf(0), bytes, length)
      }
    }
  } else {
    emptyBytes
  }
}

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

