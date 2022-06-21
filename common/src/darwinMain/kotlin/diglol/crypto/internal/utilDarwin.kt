package diglol.crypto.internal

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.create
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

inline fun ByteArray.toNSData(): NSData = memScoped {
  NSData.create(bytes = allocArrayOf(this@toNSData), length = size.convert())
}
