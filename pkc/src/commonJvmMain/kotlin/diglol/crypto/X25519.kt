package diglol.crypto

import kotlin.random.Random.Default.nextBytes

// https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/math/ec/rfc7748/X25519.java
actual object X25519 : Dh {
  private const val POINT_SIZE = 32
  private const val SCALAR_SIZE = 32
  private const val C_A = 486662
  private const val C_A24 = (C_A + 2) / 4

  @JvmField
  actual val KEY_SIZE: Int = X25519_KEY_SIZE

  actual override suspend fun generateKeyPair(): KeyPair = generateKeyPair(generatePrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkPrivateKey(privateKey)
    val publicKey = ByteArray(POINT_SIZE)
    scalarMultBase(privateKey, 0, publicKey, 0)
    return KeyPair(publicKey, privateKey)
  }

  actual override suspend fun compute(privateKey: ByteArray, peersPublicKey: ByteArray): ByteArray {
    checkPrivateKey(privateKey)
    checkPublicKey(peersPublicKey)
    val sharedSecret = ByteArray(POINT_SIZE)
    scalarMult(privateKey, 0, peersPublicKey, 0, sharedSecret, 0)
    return sharedSecret
  }

  private fun decode32(bs: ByteArray, off: Int): Int {
    var n: Int = bs[off].toInt() and 0xff
    n = n or (bs[off + 1].toInt() and 0xff shl 8)
    n = n or (bs[off + 2].toInt() and 0xff shl 16)
    n = n or (bs[off + 3].toInt() shl 24)
    return n
  }

  private fun decodeScalar(k: ByteArray, kOff: Int, n: IntArray) {
    for (i in 0..7) {
      n[i] = decode32(k, kOff + i * 4)
    }
    n[0] = n[0] and -0x8
    n[7] = n[7] and 0x7fffffff
    n[7] = n[7] or 0x40000000
  }

  private fun generatePrivateKey(): ByteArray {
    val k = nextBytes(SCALAR_SIZE)
    k[0] = (k[0].toInt() and 0xF8).toByte()
    k[SCALAR_SIZE - 1] = (k[SCALAR_SIZE - 1].toInt() and 0x7F).toByte()
    k[SCALAR_SIZE - 1] = (k[SCALAR_SIZE - 1].toInt() or 0x40).toByte()
    return k
  }

  private fun pointDouble(x: IntArray, z: IntArray) {
    val a = X25519Field.create()
    val b = X25519Field.create()
    X25519Field.apm(x, z, a, b)
    X25519Field.sqr(a, a)
    X25519Field.sqr(b, b)
    X25519Field.mul(a, b, x)
    X25519Field.sub(a, b, a)
    X25519Field.mul(a, C_A24, z)
    X25519Field.add(z, b, z)
    X25519Field.mul(z, a, z)
  }

  private fun scalarMult(
    k: ByteArray,
    kOff: Int,
    u: ByteArray,
    uOff: Int,
    r: ByteArray,
    rOff: Int
  ) {
    val n = IntArray(8)
    decodeScalar(k, kOff, n)
    val x1 = X25519Field.create()
    X25519Field.decode(u, uOff, x1)
    val x2 = X25519Field.create()
    X25519Field.copy(x1, 0, x2, 0)
    val z2 = X25519Field.create()
    z2[0] = 1
    val x3 = X25519Field.create()
    x3[0] = 1
    val z3 = X25519Field.create()
    val t1 = X25519Field.create()
    val t2 = X25519Field.create()
    var bit = 254
    var swap = 1
    do {
      X25519Field.apm(x3, z3, t1, x3)
      X25519Field.apm(x2, z2, z3, x2)
      X25519Field.mul(t1, x2, t1)
      X25519Field.mul(x3, z3, x3)
      X25519Field.sqr(z3, z3)
      X25519Field.sqr(x2, x2)
      X25519Field.sub(z3, x2, t2)
      X25519Field.mul(t2, C_A24, z2)
      X25519Field.add(z2, x2, z2)
      X25519Field.mul(z2, t2, z2)
      X25519Field.mul(x2, z3, x2)
      X25519Field.apm(t1, x3, x3, z3)
      X25519Field.sqr(x3, x3)
      X25519Field.sqr(z3, z3)
      X25519Field.mul(z3, x1, z3)
      --bit
      val word = bit ushr 5
      val shift = bit and 0x1F
      val kt = n[word] ushr shift and 1
      swap = swap xor kt
      X25519Field.cswap(swap, x2, x3)
      X25519Field.cswap(swap, z2, z3)
      swap = kt
    } while (bit >= 3)
    for (i in 0..2) {
      pointDouble(x2, z2)
    }
    X25519Field.inv(z2, z2)
    X25519Field.mul(x2, z2, x2)
    X25519Field.normalize(x2)
    X25519Field.encode(x2, r, rOff)
  }

  private fun scalarMultBase(k: ByteArray, kOff: Int, r: ByteArray, rOff: Int) {
    val y = X25519Field.create()
    val z = X25519Field.create()
    Ed25519.scalarMultBaseYZ(k, kOff, y, z)
    X25519Field.apm(z, y, y, z)
    X25519Field.inv(z, z)
    X25519Field.mul(y, z, y)
    X25519Field.normalize(y)
    X25519Field.encode(y, r, rOff)
  }
}
