package diglol.crypto

/**
 * HalfSipHash works with 32-bit words instead of 64-bit,
 * takes a 64-bit key, and returns 32-bit tag.
 */
object HalfSipHash {

  fun hash(key: SipKey, data: ByteArray): Int {
    var m: Int
    val s = State(key)
    val iter = data.size / 4

    for (i in 0 until iter) {
      m = data.toInt(i * 4)
      s.processBlock(m)
    }

    m = lastBlock(data, iter)
    s.processBlock(m)
    s.finish()
    return s.digest()
  }

  private fun lastBlock(data: ByteArray, iter: Int): Int {
    var last: Int = data.size shl 24
    val off = iter * 4

    when (data.size % 4) {
      3 -> {
        last = last or (data[off + 2].toUByte().toInt() shl 16)
        last = last or (data[off + 1].toUByte().toInt() shl 8)
        last = last or data[off].toUByte().toInt()
      }

      2 -> {
        last = last or (data[off + 1].toUByte().toInt() shl 8)
        last = last or data[off].toUByte().toInt()
      }

      1 -> last = last or data[off].toUByte().toInt()
      0 -> {}
    }
    return last
  }

  private class State(
    key: SipKey
  ) {

    private val k0: Int = key.leftInt()
    private val k1: Int = key.rightInt()

    private var v0: Int = 0 xor k0
    private var v1: Int = 0 xor k1
    private var v2: Int = 0x6c796765 xor k0
    private var v3: Int = 0x74656462 xor k1

    private fun compress() {
      v0 += v1
      v1 = rotateLeft(v1, 5)
      v1 = v1 xor v0
      v0 = rotateLeft(v0, 16)
      v2 += v3
      v3 = rotateLeft(v3, 8)
      v3 = v3 xor v2
      v0 += v3
      v3 = rotateLeft(v3, 7)
      v3 = v3 xor v0
      v2 += v1
      v1 = rotateLeft(v1, 13)
      v1 = v1 xor v2
      v2 = rotateLeft(v2, 16)
    }

    private fun compressTimes(times: Int) {
      for (i in 0 until times) {
        compress()
      }
    }

    fun processBlock(m: Int) {
      v3 = v3 xor m
      compressTimes(2)
      v0 = v0 xor m
    }

    fun finish() {
      v2 = v2 xor 0xff
      compressTimes(4)
    }

    fun digest(): Int = v1 xor v3
  }

  private fun rotateLeft(value: Int, shift: Int): Int = value shl shift or (value ushr 32 - shift)
}
