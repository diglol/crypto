package diglol.crypto

class SipKey(
  private val key: ByteArray
) {

  init {
    require(key.size == 8 || key.size == 16) { "SipKey's key must be 8 or 16 bytes" }
  }

  internal fun left(): Long = key.toLong(0)
  internal fun leftInt(): Int = key.toInt(0)
  internal fun right(): Long = key.toLong(8)
  internal fun rightInt(): Int = key.toInt(4)
}

internal fun ByteArray.toLong(offset: Int): Long {
  var m: Long = 0
  for (i in 0..<8) {
    m = m or (get(i + offset).toLong() and 0xffL shl 8 * i)
  }
  return m
}

internal fun ByteArray.toInt(offset: Int): Int {
  var m: Int = 0
  for (i in 0..<4) {
    m = m or (get(i + offset).toInt() and 0xff shl 8 * i)
  }
  return m
}
