package diglol.crypto.random

import diglol.crypto.internal.toByteArray
import kotlin.math.abs
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.cValue
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.value
import platform.Foundation.NSMutableData
import platform.Foundation.dataWithLength
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

actual fun nextInt(bound: Int): Int = memScoped {
  checkBound(bound)
  val value = cValue<IntVar>().ptr
  SecRandomCopyBytes(kSecRandomDefault, sizeOf<IntVar>().convert(), value)
  return abs(value.pointed.value % bound)
}

actual fun nextBytes(size: Int): ByteArray {
  val value = NSMutableData.dataWithLength(size.convert())!!
  SecRandomCopyBytes(kSecRandomDefault, size.convert(), value.mutableBytes)
  return value.toByteArray()
}
