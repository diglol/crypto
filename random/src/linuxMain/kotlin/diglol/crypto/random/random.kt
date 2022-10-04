package diglol.crypto.random

import diglol.crypto.internal.emptyBytes
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.get
import kotlinx.cinterop.usePinned
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread

actual fun nextInt(bound: Int): Int = commonNextInt(bound)

actual fun nextBytes(size: Int): ByteArray {
  if (size == 0) {
    return emptyBytes
  }
  return ByteArray(size).apply {
    usePinned {
      val ptr = it.addressOf(0)
      val file = fopen("/dev/urandom", "rb")
      if (file != null) {
        @Suppress("OPT_IN_USAGE")
        fread(ptr, 1.convert(), this.size.convert(), file)
        for (n in this.indices) this[n] = ptr[n]
        fclose(file)
      }
    }
  }
}
