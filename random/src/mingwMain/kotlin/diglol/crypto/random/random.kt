package diglol.crypto.random

import diglol.crypto.internal.emptyBytes
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.windows.BCRYPT_USE_SYSTEM_PREFERRED_RNG
import platform.windows.BCryptGenRandom

// https://docs.microsoft.com/zh-cn/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
actual fun nextInt(bound: Int): Int = commonNextInt(bound)

@OptIn(ExperimentalForeignApi::class)
actual fun nextBytes(size: Int): ByteArray {
  if (size == 0) {
    return emptyBytes
  }
  return ByteArray(size).apply {
    usePinned {
      BCryptGenRandom(
        null,
        it.addressOf(0).reinterpret(),
        this.size.convert(),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG.convert()
      )
    }
  }
}
