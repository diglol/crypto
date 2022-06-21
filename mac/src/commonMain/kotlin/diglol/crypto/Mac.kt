package diglol.crypto

interface Mac {
  enum class Alg {
    HMAC,
    POLY1305
  }

  fun size(): Int

  suspend fun compute(data: ByteArray, macSize: Int = size()): ByteArray
  suspend fun verify(mac: ByteArray, data: ByteArray): Boolean
}

internal fun Mac.checkMacSize(macSize: Int) {
  if (size() < macSize) {
    throw Error("Mac size too big")
  }
}

internal suspend fun Mac.commonVerify(mac: ByteArray, data: ByteArray): Boolean {
  if (mac.size > size()) {
    return false
  }
  return mac.contentEquals(compute(data, mac.size))
}
