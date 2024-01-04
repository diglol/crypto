package diglol.crypto

// https://datatracker.ietf.org/doc/html/rfc4634
object SipHash {

  fun hash(key: SipKey, data: ByteArray): Long {
    var m: Long
    val s = State(key)
    val iter = data.size / 8

    for (i in 0 until iter) {
      m = data.toLong(i * 8)
      s.processBlock(m)
    }

    m = lastBlock(data, iter)
    s.processBlock(m)
    s.finish()
    return s.digest()
  }

  private fun lastBlock(data: ByteArray, iter: Int): Long {
    var last = data.size.toLong() shl 56
    val off = iter * 8

    when (data.size % 8) {
      7 -> {
        last = last or (data[off + 6].toLong() shl 48)
        last = last or (data[off + 5].toLong() shl 40)
        last = last or (data[off + 4].toLong() shl 32)
        last = last or (data[off + 3].toLong() shl 24)
        last = last or (data[off + 2].toLong() shl 16)
        last = last or (data[off + 1].toLong() shl 8)
        last = last or data[off].toLong()
      }

      6 -> {
        last = last or (data[off + 5].toLong() shl 40)
        last = last or (data[off + 4].toLong() shl 32)
        last = last or (data[off + 3].toLong() shl 24)
        last = last or (data[off + 2].toLong() shl 16)
        last = last or (data[off + 1].toLong() shl 8)
        last = last or data[off].toLong()
      }

      5 -> {
        last = last or (data[off + 4].toLong() shl 32)
        last = last or (data[off + 3].toLong() shl 24)
        last = last or (data[off + 2].toLong() shl 16)
        last = last or (data[off + 1].toLong() shl 8)
        last = last or data[off].toLong()
      }

      4 -> {
        last = last or (data[off + 3].toLong() shl 24)
        last = last or (data[off + 2].toLong() shl 16)
        last = last or (data[off + 1].toLong() shl 8)
        last = last or data[off].toLong()
      }

      3 -> {
        last = last or (data[off + 2].toLong() shl 16)
        last = last or (data[off + 1].toLong() shl 8)
        last = last or data[off].toLong()
      }

      2 -> {
        last = last or (data[off + 1].toLong() shl 8)
        last = last or data[off].toLong()
      }

      1 -> last = last or data[off].toLong()
      0 -> {}
      else -> throw IllegalStateException("Unexpected offset: $off")
    }
    return last
  }

  private class State(
    key: SipKey
  ) {
    private val k0: Long = key.left()
    private val k1: Long = key.right()

    private var v0: Long = 0x736f6d6570736575L xor k0
    private var v1: Long = 0x646f72616e646f6dL xor k1
    private var v2: Long = 0x6c7967656e657261L xor k0
    private var v3: Long = 0x7465646279746573L xor k1

    private fun compress() {
      v0 += v1
      v1 = rotateLeft(v1, 13)
      v1 = v1 xor v0
      v0 = rotateLeft(v0, 32)
      v2 += v3
      v3 = rotateLeft(v3, 16)
      v3 = v3 xor v2
      v0 += v3
      v3 = rotateLeft(v3, 21)
      v3 = v3 xor v0
      v2 += v1
      v1 = rotateLeft(v1, 17)
      v1 = v1 xor v2
      v2 = rotateLeft(v2, 32)
    }

    private fun compressTimes(times: Int) {
      for (i in 0 until times) {
        compress()
      }
    }

    fun processBlock(m: Long) {
      v3 = v3 xor m
      compressTimes(2)
      v0 = v0 xor m
    }

    fun finish() {
      v2 = v2 xor 0xffL
      compressTimes(4)
    }

    fun digest(): Long = v0 xor v1 xor v2 xor v3
  }

  private fun rotateLeft(value: Long, shift: Int): Long = value shl shift or (value ushr 64 - shift)
}
