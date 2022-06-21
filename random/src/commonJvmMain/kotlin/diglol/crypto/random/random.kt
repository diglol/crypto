package diglol.crypto.random

import java.security.SecureRandom

actual fun nextInt(bound: Int): Int {
  checkBound(bound)
  return localRandom.get().nextInt(bound)
}

actual fun nextBytes(size: Int): ByteArray {
  val data = ByteArray(size)
  localRandom.get().nextBytes(data)
  return data
}

private val localRandom = object : ThreadLocal<SecureRandom>() {
  override fun initialValue(): SecureRandom {
    val random = SecureRandom()
    random.nextLong()
    return random
  }
}
