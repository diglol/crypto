package diglol.crypto.random

import diglol.crypto.internal.emptyBytes
import kotlin.math.abs
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.cValue
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

actual fun nextInt(bound: Int): Int = memScoped {
  checkBound(bound)
  val value = cValue<IntVar>().ptr
  @Suppress("OPT_IN_USAGE")
  SecRandomCopyBytes(kSecRandomDefault, sizeOf<IntVar>().convert(), value)
  return abs(value.pointed.value % bound)
}

actual fun nextBytes(size: Int): ByteArray {
  if (size == 0) {
    return emptyBytes
  }
  return ByteArray(size).apply {
    usePinned {
      @Suppress("OPT_IN_USAGE")
      SecRandomCopyBytes(kSecRandomDefault, size.convert(), it.addressOf(0))
    }
  }
}
