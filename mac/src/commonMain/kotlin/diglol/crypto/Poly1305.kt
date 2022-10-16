package diglol.crypto

import diglol.crypto.internal.selfOrCopyOf
import kotlin.jvm.JvmOverloads
import kotlin.math.min

// https://datatracker.ietf.org/doc/html/rfc7539
// https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/subtle/Poly1305.java
class Poly1305(private val key: ByteArray) : Mac {
  init {
    if (key.size != MAC_KEY_SIZE) {
      throw Error("The key length in bytes must be 32.")
    }
  }

  override fun size(): Int = MAC_TAG_SIZE

  @JvmOverloads
  override suspend fun compute(data: ByteArray, macSize: Int): ByteArray {
    checkMacSize(macSize)
    var h0: Long = 0
    var h1: Long = 0
    var h2: Long = 0
    var h3: Long = 0
    var h4: Long = 0
    var d0: Long
    var d1: Long
    var d2: Long
    var d3: Long
    var d4: Long
    var c: Long

    // r &= 0xffffffc0ffffffc0ffffffc0fffffff
    val r0 = load26(key, 0, 0) and 0x3ffffff
    val r1 = load26(key, 3, 2) and 0x3ffff03
    val r2 = load26(key, 6, 4) and 0x3ffc0ff
    val r3 = load26(key, 9, 6) and 0x3f03fff
    val r4 = load26(key, 12, 8) and 0x00fffff
    val s1 = r1 * 5
    val s2 = r2 * 5
    val s3 = r3 * 5
    val s4 = r4 * 5
    val buf = ByteArray(MAC_TAG_SIZE + 1)
    var i = 0
    while (i < data.size) {
      copyBlockSize(buf, data, i)
      h0 += load26(buf, 0, 0)
      h1 += load26(buf, 3, 2)
      h2 += load26(buf, 6, 4)
      h3 += load26(buf, 9, 6)
      h4 += load26(buf, 12, 8) or (buf[MAC_TAG_SIZE].toLong() shl 24)

      // d = r * h
      d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
      d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
      d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
      d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
      d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

      // Partial reduction mod 2^130-5, resulting h1 might not be 26bits.
      c = d0 shr 26
      h0 = d0 and 0x3ffffff
      d1 += c
      c = d1 shr 26
      h1 = d1 and 0x3ffffff
      d2 += c
      c = d2 shr 26
      h2 = d2 and 0x3ffffff
      d3 += c
      c = d3 shr 26
      h3 = d3 and 0x3ffffff
      d4 += c
      c = d4 shr 26
      h4 = d4 and 0x3ffffff
      h0 += c * 5
      c = h0 shr 26
      h0 = h0 and 0x3ffffff
      h1 += c
      i += MAC_TAG_SIZE
    }
    // Do final reduction mod 2^130-5
    c = h1 shr 26
    h1 = h1 and 0x3ffffff
    h2 += c
    c = h2 shr 26
    h2 = h2 and 0x3ffffff
    h3 += c
    c = h3 shr 26
    h3 = h3 and 0x3ffffff
    h4 += c
    c = h4 shr 26
    h4 = h4 and 0x3ffffff
    h0 += c * 5 // c * 5 can be at most 5
    c = h0 shr 26
    h0 = h0 and 0x3ffffff
    h1 += c

    // Compute h - p
    var g0 = h0 + 5
    c = g0 shr 26
    g0 = g0 and 0x3ffffff
    var g1 = h1 + c
    c = g1 shr 26
    g1 = g1 and 0x3ffffff
    var g2 = h2 + c
    c = g2 shr 26
    g2 = g2 and 0x3ffffff
    var g3 = h3 + c
    c = g3 shr 26
    g3 = g3 and 0x3ffffff
    val g4 = h4 + c - (1 shl 26)

    // Select h if h < p, or h - p if h >= p
    var mask = g4 shr 63 // mask is either 0 (h >= p) or -1 (h < p)
    h0 = h0 and mask
    h1 = h1 and mask
    h2 = h2 and mask
    h3 = h3 and mask
    h4 = h4 and mask
    mask = mask.inv()
    h0 = h0 or (g0 and mask)
    h1 = h1 or (g1 and mask)
    h2 = h2 or (g2 and mask)
    h3 = h3 or (g3 and mask)
    h4 = h4 or (g4 and mask)

    // h = h % (2^128)
    h0 = h0 or (h1 shl 26) and 0xffffffffL
    h1 = h1 shr 6 or (h2 shl 20) and 0xffffffffL
    h2 = h2 shr 12 or (h3 shl 14) and 0xffffffffL
    h3 = h3 shr 18 or (h4 shl 8) and 0xffffffffL

    // mac = (h + pad) % (2^128)
    c = h0 + load32(key, 16)
    h0 = c and 0xffffffffL
    c = h1 + load32(key, 20) + (c shr 32)
    h1 = c and 0xffffffffL
    c = h2 + load32(key, 24) + (c shr 32)
    h2 = c and 0xffffffffL
    c = h3 + load32(key, 28) + (c shr 32)
    h3 = c and 0xffffffffL
    val mac = ByteArray(MAC_TAG_SIZE)
    toByteArray(mac, h0, 0)
    toByteArray(mac, h1, 4)
    toByteArray(mac, h2, 8)
    toByteArray(mac, h3, 12)
    return mac.selfOrCopyOf(macSize)
  }

  override suspend fun verify(mac: ByteArray, data: ByteArray): Boolean = commonVerify(mac, data)

  private fun load32(input: ByteArray, idx: Int): Long {
    return ((input[idx].toLong() and 0xff
      or (input[idx + 1].toLong() and 0xff shl 8)
      or (input[idx + 2].toLong() and 0xff shl 16)
      or (input[idx + 3].toLong() and 0xff shl 24))
      and 0xffffffffL)
  }

  private fun load26(input: ByteArray, idx: Int, shift: Int): Long {
    return load32(input, idx) shr shift and 0x3ffffff
  }

  private fun toByteArray(output: ByteArray, num: Long, idx: Int) {
    output[idx] = (num shr 0 and 0xff).toByte()
    output[idx + 1] = (num shr 8 and 0xff).toByte()
    output[idx + 2] = (num shr 16 and 0xff).toByte()
    output[idx + 3] = (num shr 24 and 0xff).toByte()
  }

  private fun copyBlockSize(output: ByteArray, input: ByteArray, idx: Int) {
    val copyCount: Int = min(MAC_TAG_SIZE, input.size - idx)
    input.copyInto(output, 0, idx, idx + copyCount)
    output[copyCount] = 1
    if (copyCount != MAC_TAG_SIZE) {
      output.fill(0.toByte(), copyCount + 1, output.size)
    }
  }

  companion object {
    const val MAC_TAG_SIZE = 16
    const val MAC_KEY_SIZE = 32
  }
}
