package diglol.crypto.random

import diglol.crypto.internal.emptyBytes
import java.security.SecureRandom

actual fun nextInt(bound: Int): Int {
  checkBound(bound)
  return localRandom.get().nextInt(bound)
}

actual fun nextBytes(size: Int): ByteArray {
  if (size == 0) {
    return emptyBytes
  }
  return ByteArray(size).apply {
    localRandom.get().nextBytes(this)
  }
}

private val localRandom = object : ThreadLocal<SecureRandom>() {
  override fun initialValue(): SecureRandom {
    val random = SecureRandom()
    random.nextLong()
    return random
  }
}
