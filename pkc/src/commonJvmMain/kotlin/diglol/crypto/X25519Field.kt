package diglol.crypto

import kotlin.math.min

// https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/math/ec/rfc7748/X25519Field.java
internal object X25519Field {
  const val SIZE = 10
  private const val M24 = 0x00ffffff
  private const val M25 = 0x01ffffff
  private const val M26 = 0x03ffffff
  private const val M30 = 0x3fffffff
  private const val M32L = 0xffffffffL
  private val P32 = intArrayOf(-0x13, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, 0x7fffffff)
  private val ROOT_NEG_ONE = intArrayOf(
    0x020ea0b0, 0x0386c9d2, 0x00478c4e, 0x0035697f, 0x005e8630,
    0x01fbd7a7, 0x0340264f, 0x01f0b2b4, 0x00027e0e, 0x00570649
  )

  fun add(x: IntArray, y: IntArray, z: IntArray) {
    for (i in 0 until SIZE) {
      z[i] = x[i] + y[i]
    }
  }

  fun addOne(z: IntArray) {
    z[0] += 1
  }

  fun apm(x: IntArray, y: IntArray, zp: IntArray, zm: IntArray) {
    for (i in 0 until SIZE) {
      val xi = x[i]
      val yi = y[i]
      zp[i] = xi + yi
      zm[i] = xi - yi
    }
  }

  fun carry(z: IntArray) {
    var z0 = z[0]
    var z1 = z[1]
    var z2 = z[2]
    var z3 = z[3]
    var z4 = z[4]
    var z5 = z[5]
    var z6 = z[6]
    var z7 = z[7]
    var z8 = z[8]
    var z9 = z[9]
    z2 += z1 shr 26
    z1 = z1 and M26
    z4 += z3 shr 26
    z3 = z3 and M26
    z7 += z6 shr 26
    z6 = z6 and M26
    z9 += z8 shr 26
    z8 = z8 and M26
    z3 += z2 shr 25
    z2 = z2 and M25
    z5 += z4 shr 25
    z4 = z4 and M25
    z8 += z7 shr 25
    z7 = z7 and M25
    z0 += (z9 shr 25) * 38
    z9 = z9 and M25
    z1 += z0 shr 26
    z0 = z0 and M26
    z6 += z5 shr 26
    z5 = z5 and M26
    z2 += z1 shr 26
    z1 = z1 and M26
    z4 += z3 shr 26
    z3 = z3 and M26
    z7 += z6 shr 26
    z6 = z6 and M26
    z9 += z8 shr 26
    z8 = z8 and M26
    z[0] = z0
    z[1] = z1
    z[2] = z2
    z[3] = z3
    z[4] = z4
    z[5] = z5
    z[6] = z6
    z[7] = z7
    z[8] = z8
    z[9] = z9
  }

  fun cmov(cond: Int, x: IntArray, xOff: Int, z: IntArray, zOff: Int) {
    for (i in 0 until SIZE) {
      var z_i = z[zOff + i]
      val diff = z_i xor x[xOff + i]
      z_i = z_i xor (diff and cond)
      z[zOff + i] = z_i
    }
  }

  fun cnegate(negate: Int, z: IntArray) {
    val mask = 0 - negate
    for (i in 0 until SIZE) {
      z[i] = (z[i] xor mask) - mask
    }
  }

  fun copy(x: IntArray, xOff: Int, z: IntArray, zOff: Int) {
    for (i in 0 until SIZE) {
      z[zOff + i] = x[xOff + i]
    }
  }

  fun create(): IntArray {
    return IntArray(SIZE)
  }

  fun createTable(n: Int): IntArray {
    return IntArray(SIZE * n)
  }

  fun cswap(swap: Int, a: IntArray, b: IntArray) {
    val mask = 0 - swap
    for (i in 0 until SIZE) {
      val ai = a[i]
      val bi = b[i]
      val dummy = mask and (ai xor bi)
      a[i] = ai xor dummy
      b[i] = bi xor dummy
    }
  }

  fun decode(x: IntArray, xOff: Int, z: IntArray) {
    decode128(x, xOff, z, 0)
    decode128(x, xOff + 4, z, 5)
    z[9] = z[9] and M24
  }

  fun decode(x: ByteArray, xOff: Int, z: IntArray) {
    decode128(x, xOff, z, 0)
    decode128(x, xOff + 16, z, 5)
    z[9] = z[9] and M24
  }

  private fun decode128(ia: IntArray, off: Int, z: IntArray, zOff: Int) {
    val t0 = ia[off + 0]
    val t1 = ia[off + 1]
    val t2 = ia[off + 2]
    val t3 = ia[off + 3]
    z[zOff + 0] = t0 and M26
    z[zOff + 1] = t1 shl 6 or (t0 ushr 26) and M26
    z[zOff + 2] = t2 shl 12 or (t1 ushr 20) and M25
    z[zOff + 3] = t3 shl 19 or (t2 ushr 13) and M26
    z[zOff + 4] = t3 ushr 7
  }

  private fun decode128(bs: ByteArray, off: Int, z: IntArray, zOff: Int) {
    val t0 = decode32(bs, off + 0)
    val t1 = decode32(bs, off + 4)
    val t2 = decode32(bs, off + 8)
    val t3 = decode32(bs, off + 12)
    z[zOff + 0] = t0 and M26
    z[zOff + 1] = t1 shl 6 or (t0 ushr 26) and M26
    z[zOff + 2] = t2 shl 12 or (t1 ushr 20) and M25
    z[zOff + 3] = t3 shl 19 or (t2 ushr 13) and M26
    z[zOff + 4] = t3 ushr 7
  }

  private fun decode32(bs: ByteArray, off: Int): Int {
    @Suppress("NAME_SHADOWING")
    var off = off
    var n: Int = bs[off].toInt() and 0xff
    n = n or (bs[++off].toInt() and 0xff shl 8)
    n = n or (bs[++off].toInt() and 0xff shl 16)
    n = n or (bs[++off].toInt() shl 24)
    return n
  }

  fun encode(x: IntArray, z: IntArray, zOff: Int) {
    encode128(x, 0, z, zOff)
    encode128(x, 5, z, zOff + 4)
  }

  fun encode(x: IntArray, z: ByteArray, zOff: Int) {
    encode128(x, 0, z, zOff)
    encode128(x, 5, z, zOff + 16)
  }

  private fun encode128(x: IntArray, xOff: Int, `is`: IntArray, off: Int) {
    val x0 = x[xOff + 0]
    val x1 = x[xOff + 1]
    val x2 = x[xOff + 2]
    val x3 = x[xOff + 3]
    val x4 = x[xOff + 4]
    `is`[off + 0] = x0 or (x1 shl 26)
    `is`[off + 1] = x1 ushr 6 or (x2 shl 20)
    `is`[off + 2] = x2 ushr 12 or (x3 shl 13)
    `is`[off + 3] = x3 ushr 19 or (x4 shl 7)
  }

  private fun encode128(x: IntArray, xOff: Int, bs: ByteArray, off: Int) {
    val x0 = x[xOff + 0]
    val x1 = x[xOff + 1]
    val x2 = x[xOff + 2]
    val x3 = x[xOff + 3]
    val x4 = x[xOff + 4]
    val t0 = x0 or (x1 shl 26)
    encode32(t0, bs, off + 0)
    val t1 = x1 ushr 6 or (x2 shl 20)
    encode32(t1, bs, off + 4)
    val t2 = x2 ushr 12 or (x3 shl 13)
    encode32(t2, bs, off + 8)
    val t3 = x3 ushr 19 or (x4 shl 7)
    encode32(t3, bs, off + 12)
  }

  private fun encode32(n: Int, bs: ByteArray, off: Int) {
    @Suppress("NAME_SHADOWING")
    var off = off
    bs[off] = n.toByte()
    bs[++off] = (n ushr 8).toByte()
    bs[++off] = (n ushr 16).toByte()
    bs[++off] = (n ushr 24).toByte()
  }

  fun inv(x: IntArray, z: IntArray) {
    val t = create()
    val u = IntArray(8)
    copy(x, 0, t, 0)
    normalize(t)
    encode(t, u, 0)
    modOddInverse(P32, u, u)
    decode(u, 0, z)
  }

  fun invVar(x: IntArray, z: IntArray) {
    val t = create()
    val u = IntArray(8)
    copy(x, 0, t, 0)
    normalize(t)
    encode(t, u, 0)
    modOddInverseVar(P32, u, u)
    decode(u, 0, z)
  }

  fun isZero(x: IntArray): Int {
    var d = 0
    for (i in 0 until SIZE) {
      d = d or x[i]
    }
    d = d ushr 1 or (d and 1)
    return d - 1 shr 31
  }

  fun isZeroVar(x: IntArray): Boolean {
    return 0 != isZero(x)
  }

  fun mul(x: IntArray, y: Int, z: IntArray) {
    val x0 = x[0]
    val x1 = x[1]
    var x2 = x[2]
    val x3 = x[3]
    var x4 = x[4]
    val x5 = x[5]
    val x6 = x[6]
    var x7 = x[7]
    val x8 = x[8]
    var x9 = x[9]
    var c0: Long
    var c1: Long
    var c2: Long
    var c3: Long
    c0 = x2.toLong() * y
    x2 = c0.toInt() and M25
    c0 = c0 shr 25
    c1 = x4.toLong() * y
    x4 = c1.toInt() and M25
    c1 = c1 shr 25
    c2 = x7.toLong() * y
    x7 = c2.toInt() and M25
    c2 = c2 shr 25
    c3 = x9.toLong() * y
    x9 = c3.toInt() and M25
    c3 = c3 shr 25
    c3 *= 38
    c3 += x0.toLong() * y
    z[0] = c3.toInt() and M26
    c3 = c3 shr 26
    c1 += x5.toLong() * y
    z[5] = c1.toInt() and M26
    c1 = c1 shr 26
    c3 += x1.toLong() * y
    z[1] = c3.toInt() and M26
    c3 = c3 shr 26
    c0 += x3.toLong() * y
    z[3] = c0.toInt() and M26
    c0 = c0 shr 26
    c1 += x6.toLong() * y
    z[6] = c1.toInt() and M26
    c1 = c1 shr 26
    c2 += x8.toLong() * y
    z[8] = c2.toInt() and M26
    c2 = c2 shr 26
    z[2] = x2 + c3.toInt()
    z[4] = x4 + c0.toInt()
    z[7] = x7 + c1.toInt()
    z[9] = x9 + c2.toInt()
  }

  fun mul(x: IntArray, y: IntArray, z: IntArray) {
    var x0 = x[0]
    var y0 = y[0]
    var x1 = x[1]
    var y1 = y[1]
    var x2 = x[2]
    var y2 = y[2]
    var x3 = x[3]
    var y3 = y[3]
    var x4 = x[4]
    var y4 = y[4]
    val u0 = x[5]
    val v0 = y[5]
    val u1 = x[6]
    val v1 = y[6]
    val u2 = x[7]
    val v2 = y[7]
    val u3 = x[8]
    val v3 = y[8]
    val u4 = x[9]
    val v4 = y[9]
    var a0 = x0.toLong() * y0
    var a1 = (x0.toLong() * y1
      + x1.toLong() * y0)
    var a2 = x0.toLong() * y2 + x1.toLong() * y1 + x2.toLong() * y0
    var a3 = (x1.toLong() * y2
      + x2.toLong() * y1)
    a3 = a3 shl 1
    a3 += (x0.toLong() * y3
      + x3.toLong() * y0)
    var a4 = x2.toLong() * y2
    a4 = a4 shl 1
    a4 += x0.toLong() * y4 + x1.toLong() * y3 + x3.toLong() * y1 + x4.toLong() * y0
    var a5 = x1.toLong() * y4 + x2.toLong() * y3 + x3.toLong() * y2 + x4.toLong() * y1
    a5 = a5 shl 1
    var a6 = (x2.toLong() * y4
      + x4.toLong() * y2)
    a6 = a6 shl 1
    a6 += x3.toLong() * y3
    var a7 = (x3.toLong() * y4
      + x4.toLong() * y3)
    var a8 = x4.toLong() * y4
    a8 = a8 shl 1
    val b0 = u0.toLong() * v0
    val b1 = (u0.toLong() * v1
      + u1.toLong() * v0)
    val b2 = u0.toLong() * v2 + u1.toLong() * v1 + u2.toLong() * v0
    var b3 = (u1.toLong() * v2
      + u2.toLong() * v1)
    b3 = b3 shl 1
    b3 += (u0.toLong() * v3
      + u3.toLong() * v0)
    var b4 = u2.toLong() * v2
    b4 = b4 shl 1
    b4 += u0.toLong() * v4 + u1.toLong() * v3 + u3.toLong() * v1 + u4.toLong() * v0
    val b5 = u1.toLong() * v4 + u2.toLong() * v3 + u3.toLong() * v2 + u4.toLong() * v1
    var b6 = (u2.toLong() * v4
      + u4.toLong() * v2)
    b6 = b6 shl 1
    b6 += u3.toLong() * v3
    val b7 = (u3.toLong() * v4
      + u4.toLong() * v3)
    val b8 = u4.toLong() * v4
    a0 -= b5 * 76
    a1 -= b6 * 38
    a2 -= b7 * 38
    a3 -= b8 * 76
    a5 -= b0
    a6 -= b1
    a7 -= b2
    a8 -= b3
    x0 += u0
    y0 += v0
    x1 += u1
    y1 += v1
    x2 += u2
    y2 += v2
    x3 += u3
    y3 += v3
    x4 += u4
    y4 += v4
    val c0 = x0.toLong() * y0
    val c1 = (x0.toLong() * y1
      + x1.toLong() * y0)
    val c2 = x0.toLong() * y2 + x1.toLong() * y1 + x2.toLong() * y0
    var c3 = (x1.toLong() * y2
      + x2.toLong() * y1)
    c3 = c3 shl 1
    c3 += (x0.toLong() * y3
      + x3.toLong() * y0)
    var c4 = x2.toLong() * y2
    c4 = c4 shl 1
    c4 += x0.toLong() * y4 + x1.toLong() * y3 + x3.toLong() * y1 + x4.toLong() * y0
    var c5 = x1.toLong() * y4 + x2.toLong() * y3 + x3.toLong() * y2 + x4.toLong() * y1
    c5 = c5 shl 1
    var c6 = (x2.toLong() * y4
      + x4.toLong() * y2)
    c6 = c6 shl 1
    c6 += x3.toLong() * y3
    val c7 = (x3.toLong() * y4
      + x4.toLong() * y3)
    var c8 = x4.toLong() * y4
    c8 = c8 shl 1
    val z8: Int
    val z9: Int
    var t: Long
    t = a8 + (c3 - a3)
    z8 = t.toInt() and M26
    t = t shr 26
    t += c4 - a4 - b4
    z9 = t.toInt() and M25
    t = t shr 25
    t = a0 + (t + c5 - a5) * 38
    z[0] = t.toInt() and M26
    t = t shr 26
    t += a1 + (c6 - a6) * 38
    z[1] = t.toInt() and M26
    t = t shr 26
    t += a2 + (c7 - a7) * 38
    z[2] = t.toInt() and M25
    t = t shr 25
    t += a3 + (c8 - a8) * 38
    z[3] = t.toInt() and M26
    t = t shr 26
    t += a4 + b4 * 38
    z[4] = t.toInt() and M25
    t = t shr 25
    t += a5 + (c0 - a0)
    z[5] = t.toInt() and M26
    t = t shr 26
    t += a6 + (c1 - a1)
    z[6] = t.toInt() and M26
    t = t shr 26
    t += a7 + (c2 - a2)
    z[7] = t.toInt() and M25
    t = t shr 25
    t += z8.toLong()
    z[8] = t.toInt() and M26
    t = t shr 26
    z[9] = z9 + t.toInt()
  }

  fun negate(x: IntArray, z: IntArray) {
    for (i in 0 until SIZE) {
      z[i] = -x[i]
    }
  }

  fun normalize(z: IntArray) {
    val x = z[9] ushr 23 and 1
    reduce(z, x)
    reduce(z, -x)
  }

  fun one(z: IntArray) {
    z[0] = 1
    for (i in 1 until SIZE) {
      z[i] = 0
    }
  }

  private fun powPm5d8(x: IntArray, rx2: IntArray, rz: IntArray) {
    // z = x^((p-5)/8) = x^FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
    // (250 1s) (1 0s) (1 1s)
    // Addition chain: [1] 2 3 5 10 15 25 50 75 125 [250]
    sqr(x, rx2)
    mul(x, rx2, rx2)
    val x3 = create()
    sqr(rx2, x3)
    mul(x, x3, x3)
    sqr(x3, 2, x3)
    mul(rx2, x3, x3)
    val x10 = create()
    sqr(x3, 5, x10)
    mul(x3, x10, x10)
    val x15 = create()
    sqr(x10, 5, x15)
    mul(x3, x15, x15)
    sqr(x15, 10, x3)
    mul(x10, x3, x3)
    sqr(x3, 25, x10)
    mul(x3, x10, x10)
    sqr(x10, 25, x15)
    mul(x3, x15, x15)
    sqr(x15, 50, x3)
    mul(x10, x3, x3)
    sqr(x3, 125, x10)
    mul(x3, x10, x10)
    sqr(x10, 2, x3)
    mul(x3, x, rz)
  }

  private fun reduce(z: IntArray, x: Int) {
    var t = z[9]
    val z9 = t and M24
    t = (t shr 24) + x
    var cc = (t * 19).toLong()
    cc += z[0]
    z[0] = cc.toInt() and M26
    cc = cc shr 26
    cc += z[1]
    z[1] = cc.toInt() and M26
    cc = cc shr 26
    cc += z[2]
    z[2] = cc.toInt() and M25
    cc = cc shr 25
    cc += z[3]
    z[3] = cc.toInt() and M26
    cc = cc shr 26
    cc += z[4]
    z[4] = cc.toInt() and M25
    cc = cc shr 25
    cc += z[5]
    z[5] = cc.toInt() and M26
    cc = cc shr 26
    cc += z[6]
    z[6] = cc.toInt() and M26
    cc = cc shr 26
    cc += z[7]
    z[7] = cc.toInt() and M25
    cc = cc shr 25
    cc += z[8]
    z[8] = cc.toInt() and M26
    cc = cc shr 26
    z[9] = z9 + cc.toInt()
  }

  fun sqr(x: IntArray, z: IntArray) {
    var x0 = x[0]
    var x1 = x[1]
    var x2 = x[2]
    var x3 = x[3]
    var x4 = x[4]
    val u0 = x[5]
    val u1 = x[6]
    val u2 = x[7]
    val u3 = x[8]
    val u4 = x[9]
    var x1_2 = x1 * 2
    var x2_2 = x2 * 2
    var x3_2 = x3 * 2
    var x4_2 = x4 * 2
    var a0 = x0.toLong() * x0
    var a1 = x0.toLong() * x1_2
    var a2 = (x0.toLong() * x2_2
      + x1.toLong() * x1)
    var a3 = (x1_2.toLong() * x2_2
      + x0.toLong() * x3_2)
    val a4 = x2.toLong() * x2_2 + x0.toLong() * x4_2 + x1.toLong() * x3_2
    var a5 = (x1_2.toLong() * x4_2
      + x2_2.toLong() * x3_2)
    var a6 = (x2_2.toLong() * x4_2
      + x3.toLong() * x3)
    var a7 = x3.toLong() * x4_2
    var a8 = x4.toLong() * x4_2
    val u1_2 = u1 * 2
    val u2_2 = u2 * 2
    val u3_2 = u3 * 2
    val u4_2 = u4 * 2
    val b0 = u0.toLong() * u0
    val b1 = u0.toLong() * u1_2
    val b2 = (u0.toLong() * u2_2
      + u1.toLong() * u1)
    val b3 = (u1_2.toLong() * u2_2
      + u0.toLong() * u3_2)
    val b4 = u2.toLong() * u2_2 + u0.toLong() * u4_2 + u1.toLong() * u3_2
    val b5 = (u1_2.toLong() * u4_2
      + u2_2.toLong() * u3_2)
    val b6 = (u2_2.toLong() * u4_2
      + u3.toLong() * u3)
    val b7 = u3.toLong() * u4_2
    val b8 = u4.toLong() * u4_2
    a0 -= b5 * 38
    a1 -= b6 * 38
    a2 -= b7 * 38
    a3 -= b8 * 38
    a5 -= b0
    a6 -= b1
    a7 -= b2
    a8 -= b3
    x0 += u0
    x1 += u1
    x2 += u2
    x3 += u3
    x4 += u4
    x1_2 = x1 * 2
    x2_2 = x2 * 2
    x3_2 = x3 * 2
    x4_2 = x4 * 2
    val c0 = x0.toLong() * x0
    val c1 = x0.toLong() * x1_2
    val c2 = (x0.toLong() * x2_2
      + x1.toLong() * x1)
    val c3 = (x1_2.toLong() * x2_2
      + x0.toLong() * x3_2)
    val c4 = x2.toLong() * x2_2 + x0.toLong() * x4_2 + x1.toLong() * x3_2
    val c5 = (x1_2.toLong() * x4_2
      + x2_2.toLong() * x3_2)
    val c6 = (x2_2.toLong() * x4_2
      + x3.toLong() * x3)
    val c7 = x3.toLong() * x4_2
    val c8 = x4.toLong() * x4_2
    val z8: Int
    val z9: Int
    var t: Long
    t = a8 + (c3 - a3)
    z8 = t.toInt() and M26
    t = t shr 26
    t += c4 - a4 - b4
    z9 = t.toInt() and M25
    t = t shr 25
    t = a0 + (t + c5 - a5) * 38
    z[0] = t.toInt() and M26
    t = t shr 26
    t += a1 + (c6 - a6) * 38
    z[1] = t.toInt() and M26
    t = t shr 26
    t += a2 + (c7 - a7) * 38
    z[2] = t.toInt() and M25
    t = t shr 25
    t += a3 + (c8 - a8) * 38
    z[3] = t.toInt() and M26
    t = t shr 26
    t += a4 + b4 * 38
    z[4] = t.toInt() and M25
    t = t shr 25
    t += a5 + (c0 - a0)
    z[5] = t.toInt() and M26
    t = t shr 26
    t += a6 + (c1 - a1)
    z[6] = t.toInt() and M26
    t = t shr 26
    t += a7 + (c2 - a2)
    z[7] = t.toInt() and M25
    t = t shr 25
    t += z8.toLong()
    z[8] = t.toInt() and M26
    t = t shr 26
    z[9] = z9 + t.toInt()
  }

  private fun sqr(x: IntArray, n: Int, z: IntArray) {
    @Suppress("NAME_SHADOWING")
    var n = n
    sqr(x, z)
    while (--n > 0) {
      sqr(z, z)
    }
  }

  fun sqrtRatioVar(u: IntArray, v: IntArray, z: IntArray): Boolean {
    val uv3 = create()
    val uv7 = create()
    mul(u, v, uv3)
    sqr(v, uv7)
    mul(uv3, uv7, uv3)
    sqr(uv7, uv7)
    mul(uv7, uv3, uv7)
    val t = create()
    val x = create()
    powPm5d8(uv7, t, x)
    mul(x, uv3, x)
    val vx2 = create()
    sqr(x, vx2)
    mul(vx2, v, vx2)
    sub(vx2, u, t)
    normalize(t)
    if (isZeroVar(t)) {
      copy(x, 0, z, 0)
      return true
    }
    add(vx2, u, t)
    normalize(t)
    if (isZeroVar(t)) {
      mul(x, ROOT_NEG_ONE, z)
      return true
    }
    return false
  }

  fun sub(x: IntArray, y: IntArray, z: IntArray) {
    for (i in 0 until SIZE) {
      z[i] = x[i] - y[i]
    }
  }

  fun subOne(z: IntArray) {
    z[0] -= 1
  }

  fun zero(z: IntArray) {
    for (i in 0 until SIZE) {
      z[i] = 0
    }
  }

  private fun modOddInverse(m: IntArray, x: IntArray, z: IntArray): Int {
    val len32 = m.size
    val bits: Int = (len32 shl 5) - m[len32 - 1].countLeadingZeroBits()
    val len30 = (bits + 29) / 30
    val t = IntArray(4)
    val D = IntArray(len30)
    val E = IntArray(len30)
    val F = IntArray(len30)
    val G = IntArray(len30)
    val M = IntArray(len30)
    E[0] = 1
    encode30(bits, x, 0, G, 0)
    encode30(bits, m, 0, M, 0)
    M.copyInto(F, 0, 0, len30)
    var eta = -1
    val m0Inv32 = inverse32(M[0])
    val maxDivsteps = getMaximumDivsteps(bits)
    var divSteps = 0

    while (divSteps < maxDivsteps) {
      eta = divsteps30(eta, F[0], G[0], t)
      updateDE30(len30, D, E, t, m0Inv32, M)
      updateFG30(len30, F, G, t)
      divSteps += 30
    }

    val signF = F[len30 - 1] shr 31
    cnegate30(len30, signF, F)

    /*
     * D is in the range (-2.M, M). First, conditionally add M if D is negative, to bring it
     * into the range (-M, M). Then normalize by conditionally negating (according to signF)
     * and/or then adding M, to bring it into the range [0, M).
     */
    cnormalize30(len30, signF, D, M)
    decode30(bits, D, 0, z, 0)
    return equalTo(len30, F, 1) and equalToZero(len30, G)
  }

  private fun modOddInverseVar(m: IntArray, x: IntArray, z: IntArray): Boolean {
    val len32 = m.size
    val bits: Int = (len32 shl 5) - m[len32 - 1].countLeadingZeroBits()
    val len30 = (bits + 29) / 30
    val t = IntArray(4)
    val D = IntArray(len30)
    val E = IntArray(len30)
    val F = IntArray(len30)
    val G = IntArray(len30)
    val M = IntArray(len30)
    E[0] = 1
    encode30(bits, x, 0, G, 0)
    encode30(bits, m, 0, M, 0)
    M.copyInto(F, 0, 0, len30)

    val clzG: Int = (G[len30 - 1] or 1).countLeadingZeroBits() - (len30 * 30 + 2 - bits)
    var eta = -1 - clzG
    var lenFG = len30
    val m0Inv32 = inverse32(M[0])
    val maxDivsteps = getMaximumDivsteps(bits)
    var divsteps = 0

    while (!isZero(lenFG, G)) {
      if (divsteps >= maxDivsteps) {
        return false
      }
      divsteps += 30
      eta = divsteps30Var(eta, F[0], G[0], t)
      updateDE30(len30, D, E, t, m0Inv32, M)
      updateFG30(lenFG, F, G, t)
      val fn = F[lenFG - 1]
      val gn = G[lenFG - 1]
      var cond = lenFG - 2 shr 31
      cond = cond or (fn xor (fn shr 31))
      cond = cond or (gn xor (gn shr 31))
      if (cond == 0) {
        F[lenFG - 2] = F[lenFG - 2] or (fn shl 30)
        G[lenFG - 2] = G[lenFG - 2] or (gn shl 30)
        --lenFG
      }
    }
    val signF = F[lenFG - 1] shr 31

    /*
     * D is in the range (-2.M, M). First, conditionally add M if D is negative, to bring it
     * into the range (-M, M). Then normalize by conditionally negating (according to signF)
     * and/or then adding M, to bring it into the range [0, M).
     */
    var signD = D[len30 - 1] shr 31
    if (signD < 0) {
      signD = add30(len30, D, M)
    }
    if (signF < 0) {
      signD = negate30(len30, D)
      negate30(lenFG, F)
    }

    if (!isOne(lenFG, F)) {
      return false
    }
    if (signD < 0) {
      add30(len30, D, M)
    }
    decode30(bits, D, 0, z, 0)
    return true
  }

  private fun inverse32(d: Int): Int {
    var x = d // d.x == 1 mod 2**3
    x *= 2 - d * x // d.x == 1 mod 2**6
    x *= 2 - d * x // d.x == 1 mod 2**12
    x *= 2 - d * x // d.x == 1 mod 2**24
    x *= 2 - d * x // d.x == 1 mod 2**48
    return x
  }

  private fun add30(len30: Int, D: IntArray, M: IntArray): Int {
    var c = 0
    val last = len30 - 1
    for (i in 0 until last) {
      c += D[i] + M[i]
      D[i] = c and M30
      c = c shr 30
    }
    c += D[last] + M[last]
    D[last] = c
    c = c shr 30
    return c
  }

  private fun cnegate30(len30: Int, cond: Int, D: IntArray) {
    var c = 0
    val last = len30 - 1
    for (i in 0 until last) {
      c += (D[i] xor cond) - cond
      D[i] = c and M30
      c = c shr 30
    }
    c += (D[last] xor cond) - cond
    D[last] = c
  }

  private fun cnormalize30(len30: Int, condNegate: Int, D: IntArray, M: IntArray) {
    val last = len30 - 1
    run {
      var c = 0
      val condAdd = D[last] shr 31
      for (i in 0 until last) {
        var di = D[i] + (M[i] and condAdd)
        di = (di xor condNegate) - condNegate
        c += di
        D[i] = c and M30
        c = c shr 30
      }
      var di = D[last] + (M[last] and condAdd)
      di = (di xor condNegate) - condNegate
      c += di
      D[last] = c
    }
    run {
      var c = 0
      val condAdd = D[last] shr 31
      for (i in 0 until last) {
        val di = D[i] + (M[i] and condAdd)
        c += di
        D[i] = c and M30
        c = c shr 30
      }
      val di = D[last] + (M[last] and condAdd)
      c += di
      D[last] = c
    }
  }

  @Suppress("NAME_SHADOWING")
  private fun decode30(bits: Int, x: IntArray, xOff: Int, z: IntArray, zOff: Int) {
    var bits = bits
    var xOff = xOff
    var zOff = zOff
    var avail = 0
    var data = 0L
    while (bits > 0) {
      while (avail < min(32, bits)) {
        data = data or (x[xOff++].toLong() shl avail)
        avail += 30
      }
      z[zOff++] = data.toInt()
      data = data ushr 32
      avail -= 32
      bits -= 32
    }
  }

  private fun divsteps30(eta: Int, f0: Int, g0: Int, t: IntArray): Int {
    @Suppress("NAME_SHADOWING")
    var eta = eta
    var u = 1
    var v = 0
    var q = 0
    var r = 1
    var f = f0
    var g = g0
    for (i in 0..29) {
      var c1 = eta shr 31
      val c2 = -(g and 1)
      val x = (f xor c1) - c1
      val y = (u xor c1) - c1
      val z = (v xor c1) - c1
      g += x and c2
      q += y and c2
      r += z and c2
      c1 = c1 and c2
      eta = (eta xor c1) - (c1 + 1)
      f += g and c1
      u += q and c1
      v += r and c1
      g = g shr 1
      u = u shl 1
      v = v shl 1
    }
    t[0] = u
    t[1] = v
    t[2] = q
    t[3] = r
    return eta
  }

  private fun divsteps30Var(eta: Int, f0: Int, g0: Int, t: IntArray): Int {
    @Suppress("NAME_SHADOWING")
    var eta = eta
    var u = 1
    var v = 0
    var q = 0
    var r = 1
    var f = f0
    var g = g0
    var m: Int
    var w: Int
    var x: Int
    var y: Int
    var z: Int
    var i = 30
    var limit: Int
    var zeros: Int
    while (true) {

      // Use a sentinel bit to count zeros only up to i.
      zeros = (g or (-1 shl i)).countTrailingZeroBits()
      g = g shr zeros
      u = u shl zeros
      v = v shl zeros
      eta -= zeros
      i -= zeros
      if (i <= 0) {
        break
      }
      if (eta < 0) {
        eta = -eta
        x = f
        f = g
        g = -x
        y = u
        u = q
        q = -y
        z = v
        v = r
        r = -z

        // Handle up to 6 divsteps at once, subject to eta and i.
        limit = if (eta + 1 > i) i else eta + 1
        m = -1 ushr 32 - limit and 63
        w = f * g * (f * f - 2) and m
      } else {
        // Handle up to 4 divsteps at once, subject to eta and i.
        limit = if (eta + 1 > i) i else eta + 1
        m = -1 ushr 32 - limit and 15
        w = f + (f + 1 and 4 shl 1)
        w = -w * g and m
      }
      g += f * w
      q += u * w
      r += v * w
    }
    t[0] = u
    t[1] = v
    t[2] = q
    t[3] = r
    return eta
  }

  @Suppress("NAME_SHADOWING")
  private fun encode30(bits: Int, x: IntArray, xOff: Int, z: IntArray, zOff: Int) {
    var bits = bits
    var xOff = xOff
    var zOff = zOff
    var avail = 0
    var data = 0L
    while (bits > 0) {
      if (avail < min(30, bits)) {
        data = data or (x[xOff++].toLong() and M32L shl avail)
        avail += 32
      }
      z[zOff++] = data.toInt() and M30
      data = data ushr 30
      avail -= 30
      bits -= 30
    }
  }

  private fun getMaximumDivsteps(bits: Int): Int {
    return (49 * bits + if (bits < 46) 80 else 47) / 17
  }

  private fun negate30(len30: Int, D: IntArray): Int {
    var c = 0
    val last = len30 - 1
    for (i in 0 until last) {
      c -= D[i]
      D[i] = c and M30
      c = c shr 30
    }
    c -= D[last]
    D[last] = c
    c = c shr 30
    return c
  }

  private fun updateDE30(
    len30: Int,
    D: IntArray,
    E: IntArray,
    t: IntArray,
    m0Inv32: Int,
    M: IntArray
  ) {
    val u = t[0]
    val v = t[1]
    val q = t[2]
    val r = t[3]
    var di: Int
    var ei: Int
    var i: Int
    var md: Int
    var me: Int
    var mi: Int
    val sd: Int
    val se: Int
    var cd: Long
    var ce: Long

    /*
     * We accept D (E) in the range (-2.M, M) and conceptually add the modulus to the input
     * value if it is initially negative. Instead of adding it explicitly, we add u and/or v (q
     * and/or r) to md (me).
     */
    sd = D[len30 - 1] shr 31
    se = E[len30 - 1] shr 31
    md = (u and sd) + (v and se)
    me = (q and sd) + (r and se)
    mi = M[0]
    di = D[0]
    ei = E[0]
    cd = u.toLong() * di + v.toLong() * ei
    ce = q.toLong() * di + r.toLong() * ei

    /*
     * Subtract from md/me an extra term in the range [0, 2^30) such that the low 30 bits of the
     * intermediate D/E values will be 0, allowing clean division by 2^30. The final D/E are
     * thus in the range (-2.M, M), consistent with the input constraint.
     */
    md -= m0Inv32 * cd.toInt() + md and M30
    me -= m0Inv32 * ce.toInt() + me and M30
    cd += mi.toLong() * md
    ce += mi.toLong() * me
    cd = cd shr 30
    ce = ce shr 30
    i = 1
    while (i < len30) {
      mi = M[i]
      di = D[i]
      ei = E[i]
      cd += u.toLong() * di + v.toLong() * ei + mi.toLong() * md
      ce += q.toLong() * di + r.toLong() * ei + mi.toLong() * me
      D[i - 1] = cd.toInt() and M30
      cd = cd shr 30
      E[i - 1] = ce.toInt() and M30
      ce = ce shr 30
      ++i
    }
    D[len30 - 1] = cd.toInt()
    E[len30 - 1] = ce.toInt()
  }

  private fun updateFG30(len30: Int, F: IntArray, G: IntArray, t: IntArray) {
    val u = t[0]
    val v = t[1]
    val q = t[2]
    val r = t[3]
    var fi: Int
    var gi: Int
    var i: Int
    var cf: Long
    var cg: Long
    fi = F[0]
    gi = G[0]
    cf = u.toLong() * fi + v.toLong() * gi
    cg = q.toLong() * fi + r.toLong() * gi
    cf = cf shr 30
    cg = cg shr 30
    i = 1
    while (i < len30) {
      fi = F[i]
      gi = G[i]
      cf += u.toLong() * fi + v.toLong() * gi
      cg += q.toLong() * fi + r.toLong() * gi
      F[i - 1] = cf.toInt() and M30
      cf = cf shr 30
      G[i - 1] = cg.toInt() and M30
      cg = cg shr 30
      ++i
    }
    F[len30 - 1] = cf.toInt()
    G[len30 - 1] = cg.toInt()
  }

  private fun equalTo(len: Int, x: IntArray, y: Int): Int {
    var d = x[0] xor y
    for (i in 1 until len) {
      d = d or x[i]
    }
    d = d ushr 1 or (d and 1)
    return d - 1 shr 31
  }

  private fun equalToZero(len: Int, x: IntArray): Int {
    var d = 0
    for (i in 0 until len) {
      d = d or x[i]
    }
    d = d ushr 1 or (d and 1)
    return d - 1 shr 31
  }

  private fun isOne(len: Int, x: IntArray): Boolean {
    if (x[0] != 1) {
      return false
    }
    for (i in 1 until len) {
      if (x[i] != 0) {
        return false
      }
    }
    return true
  }

  private fun isZero(len: Int, x: IntArray): Boolean {
    for (i in 0 until len) {
      if (x[i] != 0) {
        return false
      }
    }
    return true
  }
}
