package diglol.crypto.random

import diglol.crypto.internal.emptyBytes
import kotlinx.cinterop.CFunction
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.invoke
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.windows.BCRYPT_ALG_HANDLE
import platform.windows.GetProcAddress
import platform.windows.LoadLibraryA
import platform.windows.PUCHAR
import platform.windows.ULONG

// https://docs.microsoft.com/zh-cn/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
private val bcrypt by lazy { LoadLibraryA("Bcrypt.dll") }
private val bcryptGenRandom by lazy {
  GetProcAddress(bcrypt, "BCryptGenRandom")
    ?.reinterpret<CFunction<Function4<BCRYPT_ALG_HANDLE?, PUCHAR?, ULONG, ULONG, Int>>>()
    ?: error("Can't find Bcrypt#BCryptGenRandom()")
}

actual fun nextInt(bound: Int): Int = commonNextInt(bound)

actual fun nextBytes(size: Int): ByteArray {
  return if (size != 0) {
    ByteArray(size).apply {
      usePinned {
        bcryptGenRandom(null, it.addressOf(0).reinterpret(), this.size.convert(), 2.convert())
      }
    }
  } else {
    emptyBytes
  }
}
