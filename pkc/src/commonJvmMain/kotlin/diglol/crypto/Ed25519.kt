package diglol.crypto

// https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed25519.java
actual object Ed25519 : Dsa {
  private const val M = 0xffffffffL
  private const val M08L = 0x000000ffL
  private const val M28L = 0x0fffffffL
  private const val M32L = 0xffffffffL
  private const val COORD_INTS = 8
  private const val POINT_BYTES = COORD_INTS * 4
  private const val SCALAR_INTS = 8
  private const val SCALAR_BYTES = SCALAR_INTS * 4
  private const val PUBLIC_KEY_SIZE = POINT_BYTES
  private const val SECRET_KEY_SIZE = 32
  private const val SIGNATURE_SIZE = POINT_BYTES + SCALAR_BYTES

  private val P = intArrayOf(-0x13, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, 0x7fffffff)
  private val L = intArrayOf(
    0x5cf5d3ed, 0x5812631a, -0x5d08632a, 0x14def9de, 0x00000000, 0x00000000, 0x00000000, 0x10000000
  )
  private const val L0 = -0x30a2c13 // L0:26/--
  private const val L1 = 0x012631a6 // L1:24/22
  private const val L2 = 0x079cd658 // L2:27/--
  private const val L3 = -0x6215d1 // L3:23/--
  private const val L4 = 0x000014df // L4:12/11
  private val B_x = intArrayOf(
    0x0325d51a, 0x018b5823, 0x007b2c95, 0x0304a92d, 0x00d2598e, 0x01d6dc5c, 0x01388c7f, 0x013fec0a,
    0x029e6b72, 0x0042d26d
  )
  private val B_y = intArrayOf(
    0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00cccccc, 0x02666666, 0x01999999, 0x00666666,
    0x03333333, 0x00cccccc
  )
  private val C_d = intArrayOf(
    0x035978a3, 0x02d37284, 0x018ab75e, 0x026a0a0e, 0x0000e014, 0x0379e898, 0x01d01e5d, 0x01e738cc,
    0x03715b7f, 0x00a406d9
  )
  private val C_d2 = intArrayOf(
    0x02b2f159, 0x01a6e509, 0x01156ebd, 0x00d4141d, 0x0001c029, 0x02f3d130, 0x03a03cbb, 0x01ce7198,
    0x02e2b6ff, 0x00480db3
  )
  private val C_d4 = intArrayOf(
    0x0165e2b2, 0x034dca13, 0x002add7a, 0x01a8283b, 0x00038052, 0x01e7a260, 0x03407977, 0x019ce331,
    0x01c56dff, 0x00901b67
  )
  private const val WNAF_WIDTH_BASE = 7
  private const val PRECOMP_BLOCKS = 8
  private const val PRECOMP_TEETH = 4
  private const val PRECOMP_SPACING = 8
  private const val PRECOMP_POINTS = 1 shl PRECOMP_TEETH - 1
  private const val PRECOMP_MASK = PRECOMP_POINTS - 1

  private val precompBaseTable: Array<PointExt>
  private val precompBase: IntArray
  private val sha512 = Hash(Hash.Type.SHA512)

  init {
    // Precomputed table for the base point in verification ladder
    val b = PointExt()
    X25519Field.copy(B_x, 0, b.x, 0)
    X25519Field.copy(B_y, 0, b.y, 0)
    pointExtendXY(b)
    precompBaseTable = pointPrecomputeVar(b, 1 shl WNAF_WIDTH_BASE - 2)
    val p = PointAccum()
    X25519Field.copy(B_x, 0, p.x, 0)
    X25519Field.copy(B_y, 0, p.y, 0)
    pointExtendXY(p)
    precompBase = X25519Field.createTable(PRECOMP_BLOCKS * PRECOMP_POINTS * 3)

    var off = 0
    @Suppress("NAME_SHADOWING") for (b in 0 until PRECOMP_BLOCKS) {
      @Suppress("UNCHECKED_CAST") val ds = arrayOfNulls<PointExt>(PRECOMP_TEETH) as Array<PointExt>
      val sum = PointExt()
      pointSetNeutral(sum)

      for (t in 0 until PRECOMP_TEETH) {
        val q = pointCopy(p)
        pointAddVar(true, sum, q, sum)
        pointDouble(p)
        ds[t] = pointCopy(p)
        if (b + t != PRECOMP_BLOCKS + PRECOMP_TEETH - 2) {
          for (s in 1 until PRECOMP_SPACING) {
            pointDouble(p)
          }
        }
      }

      @Suppress("UNCHECKED_CAST") val points =
        arrayOfNulls<PointExt>(PRECOMP_POINTS) as Array<PointExt>
      var k = 0
      points[k++] = sum
      for (t in 0 until PRECOMP_TEETH - 1) {
        val size = 1 shl t
        var j = 0
        while (j < size) {
          pointAddVar(false, points[k - size], ds[t], PointExt().also { points[k] = it })
          ++j
          ++k
        }
      }

      val cs = X25519Field.createTable(PRECOMP_POINTS)
      // TODO[ed25519] A single batch inversion across all blocks?
      run {
        val u = X25519Field.create()
        X25519Field.copy(points[0].z, 0, u, 0)
        X25519Field.copy(u, 0, cs, 0)

        var i = 0
        while (++i < PRECOMP_POINTS) {
          X25519Field.mul(u, points[i].z, u)
          X25519Field.copy(u, 0, cs, i * X25519Field.SIZE)
        }
        X25519Field.add(u, u, u)
        X25519Field.invVar(u, u)
        --i
        val t = X25519Field.create()
        while (i > 0) {
          val j = i--
          X25519Field.copy(cs, i * X25519Field.SIZE, t, 0)
          X25519Field.mul(t, u, t)
          X25519Field.copy(t, 0, cs, j * X25519Field.SIZE)
          X25519Field.mul(u, points[j].z, u)
        }
        X25519Field.copy(u, 0, cs, 0)
      }

      for (i in 0 until PRECOMP_POINTS) {
        val q = points[i]
        val x = X25519Field.create()
        val y = X25519Field.create()
        X25519Field.copy(cs, i * X25519Field.SIZE, y, 0)
        X25519Field.mul(q.x, y, x)
        X25519Field.mul(q.y, y, y)
        val r = PointPrecomp()
        X25519Field.apm(y, x, r.ypx_h, r.ymx_h)
        X25519Field.mul(x, y, r.xyd)
        X25519Field.mul(r.xyd, C_d4, r.xyd)
        X25519Field.normalize(r.ypx_h)
        X25519Field.normalize(r.ymx_h)
        X25519Field.copy(r.ypx_h, 0, precompBase, off)
        off += X25519Field.SIZE
        X25519Field.copy(r.ymx_h, 0, precompBase, off)
        off += X25519Field.SIZE
        X25519Field.copy(r.xyd, 0, precompBase, off)
        off += X25519Field.SIZE
      }
    }
  }

  actual override suspend fun generateKeyPair(): KeyPair =
    generateKeyPair(generateEd25519PrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkEd25519PrivateKey(privateKey)
    val publicKey = ByteArray(PUBLIC_KEY_SIZE)
    generatePublicKey(privateKey, 0, publicKey, 0)
    return KeyPair(publicKey, privateKey)
  }

  actual override suspend fun sign(privateKey: ByteArray, data: ByteArray): ByteArray {
    val keyPair = generateKeyPair(privateKey)
    val signature = ByteArray(SIGNATURE_SIZE)
    sign(keyPair.privateKey, 0, keyPair.publicKey, 0, data, 0, data.size, signature, 0)
    return signature
  }

  actual suspend fun sign(keyPair: KeyPair, data: ByteArray): ByteArray {
    val signature = ByteArray(SIGNATURE_SIZE)
    sign(keyPair.privateKey, 0, keyPair.publicKey, 0, data, 0, data.size, signature, 0)
    return signature
  }

  actual override suspend fun verify(
    signature: ByteArray,
    publicKey: ByteArray,
    data: ByteArray
  ): Boolean {
    checkEd25519Signature(signature)
    checkEd25519PublicKey(publicKey)
    return verify(signature, 0, publicKey, 0, data, 0, data.size)
  }

  private suspend fun generatePublicKey(sk: ByteArray, skOff: Int, pk: ByteArray, pkOff: Int) {
    val h: ByteArray = sha512.hash(sk.copyOfRange(skOff, skOff + SECRET_KEY_SIZE))
    val s = ByteArray(SCALAR_BYTES)
    pruneScalar(h, 0, s)
    scalarMultBaseEncoded(s, pk, pkOff)
  }

  private suspend fun implSign(
    h: ByteArray,
    s: ByteArray,
    pk: ByteArray,
    pkOff: Int,
    m: ByteArray,
    mOff: Int,
    mLen: Int,
    sig: ByteArray,
    sigOff: Int
  ) {
    @Suppress("NAME_SHADOWING") var h =
      h.copyOfRange(SCALAR_BYTES, SCALAR_BYTES + SECRET_KEY_SIZE) + m.copyOfRange(mOff, mOff + mLen)
    h = sha512.hash(h)
    val r = reduceScalar(h)
    val R = ByteArray(POINT_BYTES)
    scalarMultBaseEncoded(r, R, 0)

    h = R.copyOf(POINT_BYTES) + pk.copyOfRange(pkOff, pkOff + POINT_BYTES) + m.copyOfRange(
      mOff, mOff + mLen
    )
    h = sha512.hash(h)
    val k = reduceScalar(h)
    val S = calculateS(r, k, s)
    R.copyInto(sig, sigOff, 0, POINT_BYTES)
    S.copyInto(sig, sigOff + POINT_BYTES, 0, SCALAR_BYTES)
  }

  private suspend fun sign(
    sk: ByteArray,
    skOff: Int,
    pk: ByteArray,
    pkOff: Int,
    m: ByteArray,
    mOff: Int,
    mLen: Int,
    sig: ByteArray,
    sigOff: Int
  ) {
    val h: ByteArray = sha512.hash(sk.copyOfRange(skOff, skOff + SECRET_KEY_SIZE))
    val s = ByteArray(SCALAR_BYTES)
    pruneScalar(h, 0, s)
    implSign(h, s, pk, pkOff, m, mOff, mLen, sig, sigOff)
  }

  private suspend fun verify(
    sig: ByteArray,
    sigOff: Int,
    pk: ByteArray,
    pkOff: Int,
    m: ByteArray,
    mOff: Int,
    mLen: Int
  ): Boolean {
    val r = sig.copyOfRange(sigOff, sigOff + POINT_BYTES)
    val s = sig.copyOfRange(sigOff + POINT_BYTES, sigOff + POINT_BYTES + SCALAR_BYTES)
    if (!checkPointVar(r)) {
      return false
    }
    val nS = IntArray(SCALAR_INTS)
    if (!checkScalarVar(s, nS)) {
      return false
    }
    val pA = PointAffine()
    return if (decodePointVar(pk, pkOff, true, pA)) {
      var h = r.copyOf(POINT_BYTES) + pk.copyOfRange(pkOff, pkOff + POINT_BYTES) + m.copyOfRange(
        mOff, mOff + mLen
      )
      h = sha512.hash(h)
      val k = reduceScalar(h)
      val nA = IntArray(SCALAR_INTS)
      decodeScalar(k, 0, nA)
      val pR = PointAccum()
      scalarMultStrausVar(nS, nA, pA, pR)
      val check = ByteArray(POINT_BYTES)
      0 != encodePoint(pR, check, 0) && check.contentEquals(r)
    } else {
      false
    }
  }

  private fun calculateS(r: ByteArray, k: ByteArray, s: ByteArray): ByteArray {
    val t = IntArray(SCALAR_INTS * 2)
    decodeScalar(r, 0, t)
    val u = IntArray(SCALAR_INTS)
    decodeScalar(k, 0, u)
    val v = IntArray(SCALAR_INTS)
    decodeScalar(s, 0, v)

    mulAddTo(u, v, t)
    val result = ByteArray(SCALAR_BYTES * 2)
    for (i in t.indices) {
      encode32(t[i], result, i * 4)
    }
    return reduceScalar(result)
  }

  private fun checkPoint(x: IntArray, y: IntArray): Int {
    val t = X25519Field.create()
    val u = X25519Field.create()
    val v = X25519Field.create()
    X25519Field.sqr(x, u)
    X25519Field.sqr(y, v)
    X25519Field.mul(u, v, t)
    X25519Field.sub(v, u, v)
    X25519Field.mul(t, C_d, t)
    X25519Field.addOne(t)
    X25519Field.sub(t, v, t)
    X25519Field.normalize(t)
    return X25519Field.isZero(t)
  }

  private fun checkPoint(x: IntArray, y: IntArray, z: IntArray): Int {
    val t = X25519Field.create()
    val u = X25519Field.create()
    val v = X25519Field.create()
    val w = X25519Field.create()
    X25519Field.sqr(x, u)
    X25519Field.sqr(y, v)
    X25519Field.sqr(z, w)
    X25519Field.mul(u, v, t)
    X25519Field.sub(v, u, v)
    X25519Field.mul(v, w, v)
    X25519Field.sqr(w, w)
    X25519Field.mul(t, C_d, t)
    X25519Field.add(t, w, t)
    X25519Field.sub(t, v, t)
    X25519Field.normalize(t)
    return X25519Field.isZero(t)
  }

  private fun checkPointVar(p: ByteArray): Boolean {
    val t = IntArray(COORD_INTS)
    decode32(p, 0, t, 0, COORD_INTS)
    t[COORD_INTS - 1] = t[COORD_INTS - 1] and 0x7FFFFFFF
    return !gte(t, P)
  }

  private fun checkScalarVar(s: ByteArray, n: IntArray): Boolean {
    decodeScalar(s, 0, n)
    return !gte(n, L)
  }

  private fun decode24(bs: ByteArray, off: Int): Int {
    @Suppress("NAME_SHADOWING") var off = off
    var n: Int = bs[off].toInt() and 0xFF
    n = n or (bs[++off].toInt() and 0xFF shl 8)
    n = n or (bs[++off].toInt() and 0xFF shl 16)
    return n
  }

  private fun decode32(bs: ByteArray, off: Int): Int {
    @Suppress("NAME_SHADOWING") var off = off
    var n: Int = bs[off].toInt() and 0xFF
    n = n or (bs[++off].toInt() and 0xFF shl 8)
    n = n or (bs[++off].toInt() and 0xFF shl 16)
    n = n or (bs[++off].toInt() shl 24)
    return n
  }

  private fun decode32(bs: ByteArray, bsOff: Int, n: IntArray, nOff: Int, nLen: Int) {
    for (i in 0 until nLen) {
      n[nOff + i] = decode32(bs, bsOff + i * 4)
    }
  }

  private fun decodePointVar(p: ByteArray, pOff: Int, negate: Boolean, r: PointAffine): Boolean {
    val py = p.copyOfRange(pOff, pOff + POINT_BYTES)
    if (!checkPointVar(py)) {
      return false
    }
    val x_0: Int = py[POINT_BYTES - 1].toInt() and 0x80 ushr 7
    py[POINT_BYTES - 1] = (py[POINT_BYTES - 1].toInt() and 0x7F).toByte()
    X25519Field.decode(py, 0, r.y)
    val u = X25519Field.create()
    val v = X25519Field.create()
    X25519Field.sqr(r.y, u)
    X25519Field.mul(C_d, u, v)
    X25519Field.subOne(u)
    X25519Field.addOne(v)
    if (!X25519Field.sqrtRatioVar(u, v, r.x)) {
      return false
    }
    X25519Field.normalize(r.x)
    if (x_0 == 1 && X25519Field.isZeroVar(r.x)) {
      return false
    }
    if (negate xor (x_0 != r.x[0] and 1)) {
      X25519Field.negate(r.x, r.x)
    }
    return true
  }

  private fun decodeScalar(k: ByteArray, kOff: Int, n: IntArray) {
    decode32(k, kOff, n, 0, SCALAR_INTS)
  }

  private fun encode24(n: Int, bs: ByteArray, off: Int) {
    @Suppress("NAME_SHADOWING") var off = off
    bs[off] = n.toByte()
    bs[++off] = (n ushr 8).toByte()
    bs[++off] = (n ushr 16).toByte()
  }

  private fun encode32(n: Int, bs: ByteArray, off: Int) {
    @Suppress("NAME_SHADOWING") var off = off
    bs[off] = n.toByte()
    bs[++off] = (n ushr 8).toByte()
    bs[++off] = (n ushr 16).toByte()
    bs[++off] = (n ushr 24).toByte()
  }

  private fun encode56(n: Long, bs: ByteArray, off: Int) {
    encode32(n.toInt(), bs, off)
    encode24((n ushr 32).toInt(), bs, off + 4)
  }

  private fun encodePoint(p: PointAccum, r: ByteArray, rOff: Int): Int {
    val x = X25519Field.create()
    val y = X25519Field.create()
    X25519Field.inv(p.z, y)
    X25519Field.mul(p.x, y, x)
    X25519Field.mul(p.y, y, y)
    X25519Field.normalize(x)
    X25519Field.normalize(y)
    val result = checkPoint(x, y)
    X25519Field.encode(y, r, rOff)
    r[rOff + POINT_BYTES - 1] = (r[rOff + POINT_BYTES - 1].toInt() or (x[0] and 1 shl 7)).toByte()
    return result
  }

  private fun getWnafVar(n: IntArray, width: Int): ByteArray {
    val t = IntArray(SCALAR_INTS * 2)
    run {
      var tPos = t.size
      var c = 0
      var i = SCALAR_INTS
      while (--i >= 0) {
        val next = n[i]
        t[--tPos] = next ushr 16 or (c shl 16)
        c = next
        t[--tPos] = c
      }
    }
    val ws = ByteArray(253)
    val lead = 32 - width
    var j = 0
    var carry = 0
    var i = 0
    while (i < t.size) {
      val word = t[i]
      while (j < 16) {
        val word16 = word ushr j
        val bit = word16 and 1
        if (bit == carry) {
          ++j
          continue
        }
        val digit = word16 or 1 shl lead
        carry = digit ushr 31
        ws[(i shl 4) + j] = (digit shr lead).toByte()
        j += width
      }
      ++i
      j -= 16
    }
    return ws
  }

  private fun pointAddVar(negate: Boolean, p: PointExt, r: PointAccum) {
    val a = X25519Field.create()
    val b = X25519Field.create()
    val c = X25519Field.create()
    val d = X25519Field.create()
    val e = r.u
    val f = X25519Field.create()
    val g = X25519Field.create()
    val h = r.v
    val nc: IntArray
    val nd: IntArray
    val nf: IntArray
    val ng: IntArray
    if (negate) {
      nc = d
      nd = c
      nf = g
      ng = f
    } else {
      nc = c
      nd = d
      nf = f
      ng = g
    }
    X25519Field.apm(r.y, r.x, b, a)
    X25519Field.apm(p.y, p.x, nd, nc)
    X25519Field.mul(a, c, a)
    X25519Field.mul(b, d, b)
    X25519Field.mul(r.u, r.v, c)
    X25519Field.mul(c, p.t, c)
    X25519Field.mul(c, C_d2, c)
    X25519Field.mul(r.z, p.z, d)
    X25519Field.add(d, d, d)
    X25519Field.apm(b, a, h, e)
    X25519Field.apm(d, c, ng, nf)
    X25519Field.carry(ng)
    X25519Field.mul(e, f, r.x)
    X25519Field.mul(g, h, r.y)
    X25519Field.mul(f, g, r.z)
  }

  private fun pointAddVar(negate: Boolean, p: PointExt, q: PointExt, r: PointExt) {
    val a = X25519Field.create()
    val b = X25519Field.create()
    val c = X25519Field.create()
    val d = X25519Field.create()
    val e = X25519Field.create()
    val f = X25519Field.create()
    val g = X25519Field.create()
    val h = X25519Field.create()
    val nc: IntArray
    val nd: IntArray
    val nf: IntArray
    val ng: IntArray
    if (negate) {
      nc = d
      nd = c
      nf = g
      ng = f
    } else {
      nc = c
      nd = d
      nf = f
      ng = g
    }
    X25519Field.apm(p.y, p.x, b, a)
    X25519Field.apm(q.y, q.x, nd, nc)
    X25519Field.mul(a, c, a)
    X25519Field.mul(b, d, b)
    X25519Field.mul(p.t, q.t, c)
    X25519Field.mul(c, C_d2, c)
    X25519Field.mul(p.z, q.z, d)
    X25519Field.add(d, d, d)
    X25519Field.apm(b, a, h, e)
    X25519Field.apm(d, c, ng, nf)
    X25519Field.carry(ng)
    X25519Field.mul(e, f, r.x)
    X25519Field.mul(g, h, r.y)
    X25519Field.mul(f, g, r.z)
    X25519Field.mul(e, h, r.t)
  }

  private fun pointAddPrecomp(p: PointPrecomp, r: PointAccum) {
    val a = X25519Field.create()
    val b = X25519Field.create()
    val c = X25519Field.create()
    val e = r.u
    val f = X25519Field.create()
    val g = X25519Field.create()
    val h = r.v
    X25519Field.apm(r.y, r.x, b, a)
    X25519Field.mul(a, p.ymx_h, a)
    X25519Field.mul(b, p.ypx_h, b)
    X25519Field.mul(r.u, r.v, c)
    X25519Field.mul(c, p.xyd, c)
    X25519Field.apm(b, a, h, e)
    X25519Field.apm(r.z, c, g, f)
    X25519Field.carry(g)
    X25519Field.mul(e, f, r.x)
    X25519Field.mul(g, h, r.y)
    X25519Field.mul(f, g, r.z)
  }

  private fun pointCopy(p: PointAccum): PointExt {
    val r = PointExt()
    X25519Field.copy(p.x, 0, r.x, 0)
    X25519Field.copy(p.y, 0, r.y, 0)
    X25519Field.copy(p.z, 0, r.z, 0)
    X25519Field.mul(p.u, p.v, r.t)
    return r
  }

  private fun pointCopy(p: PointAffine): PointExt {
    val r = PointExt()
    X25519Field.copy(p.x, 0, r.x, 0)
    X25519Field.copy(p.y, 0, r.y, 0)
    pointExtendXY(r)
    return r
  }

  private fun pointCopy(p: PointExt): PointExt {
    val r = PointExt()
    pointCopy(p, r)
    return r
  }

  private fun pointCopy(p: PointExt, r: PointExt) {
    X25519Field.copy(p.x, 0, r.x, 0)
    X25519Field.copy(p.y, 0, r.y, 0)
    X25519Field.copy(p.z, 0, r.z, 0)
    X25519Field.copy(p.t, 0, r.t, 0)
  }

  private fun pointDouble(r: PointAccum) {
    val a = X25519Field.create()
    val b = X25519Field.create()
    val c = X25519Field.create()
    val e = r.u
    val f = X25519Field.create()
    val g = X25519Field.create()
    val h = r.v
    X25519Field.sqr(r.x, a)
    X25519Field.sqr(r.y, b)
    X25519Field.sqr(r.z, c)
    X25519Field.add(c, c, c)
    X25519Field.apm(a, b, h, g)
    X25519Field.add(r.x, r.y, e)
    X25519Field.sqr(e, e)
    X25519Field.sub(h, e, e)
    X25519Field.add(c, g, f)
    X25519Field.carry(f)
    X25519Field.mul(e, f, r.x)
    X25519Field.mul(g, h, r.y)
    X25519Field.mul(f, g, r.z)
  }

  private fun pointExtendXY(p: PointAccum) {
    X25519Field.one(p.z)
    X25519Field.copy(p.x, 0, p.u, 0)
    X25519Field.copy(p.y, 0, p.v, 0)
  }

  private fun pointExtendXY(p: PointExt) {
    X25519Field.one(p.z)
    X25519Field.mul(p.x, p.y, p.t)
  }

  private fun pointLookup(block: Int, index: Int, p: PointPrecomp) {
    var off = block * PRECOMP_POINTS * 3 * X25519Field.SIZE
    for (i in 0 until PRECOMP_POINTS) {
      val cond = (i xor index) - 1 shr 31
      X25519Field.cmov(cond, precompBase, off, p.ypx_h, 0)
      off += X25519Field.SIZE
      X25519Field.cmov(cond, precompBase, off, p.ymx_h, 0)
      off += X25519Field.SIZE
      X25519Field.cmov(cond, precompBase, off, p.xyd, 0)
      off += X25519Field.SIZE
    }
  }

  private fun pointPrecomputeVar(p: PointExt, count: Int): Array<PointExt> {
    val d = PointExt()
    pointAddVar(false, p, p, d)
    @Suppress("UNCHECKED_CAST") val table = arrayOfNulls<PointExt>(count) as Array<PointExt>
    table[0] = pointCopy(p)
    for (i in 1 until count) {
      pointAddVar(false, table[i - 1], d, PointExt().also {
        table[i] = it
      })
    }
    return table
  }

  private fun pointSetNeutral(p: PointAccum) {
    X25519Field.zero(p.x)
    X25519Field.one(p.y)
    X25519Field.one(p.z)
    X25519Field.zero(p.u)
    X25519Field.one(p.v)
  }

  private fun pointSetNeutral(p: PointExt) {
    X25519Field.zero(p.x)
    X25519Field.one(p.y)
    X25519Field.one(p.z)
    X25519Field.zero(p.t)
  }

  private fun pruneScalar(n: ByteArray, nOff: Int, r: ByteArray) {
    n.copyInto(r, 0, nOff, nOff + SCALAR_BYTES)
    r[0] = (r[0].toInt() and 0xF8).toByte()
    r[SCALAR_BYTES - 1] = (r[SCALAR_BYTES - 1].toInt() and 0x7F).toByte()
    r[SCALAR_BYTES - 1] = (r[SCALAR_BYTES - 1].toInt() or 0x40).toByte()
  }

  private fun reduceScalar(n: ByteArray): ByteArray {
    var x00 = decode32(n, 0).toLong() and M32L // x00:32/--
    var x01 = decode24(n, 4).toLong() shl 4 and M32L // x01:28/--
    var x02 = decode32(n, 7).toLong() and M32L // x02:32/--
    var x03 = decode24(n, 11).toLong() shl 4 and M32L // x03:28/--
    var x04 = decode32(n, 14).toLong() and M32L // x04:32/--
    var x05 = decode24(n, 18).toLong() shl 4 and M32L // x05:28/--
    var x06 = decode32(n, 21).toLong() and M32L // x06:32/--
    var x07 = decode24(n, 25).toLong() shl 4 and M32L // x07:28/--
    var x08 = decode32(n, 28).toLong() and M32L // x08:32/--
    var x09 = decode24(n, 32).toLong() shl 4 and M32L // x09:28/--
    var x10 = decode32(n, 35).toLong() and M32L // x10:32/--
    var x11 = decode24(n, 39).toLong() shl 4 and M32L // x11:28/--
    var x12 = decode32(n, 42).toLong() and M32L // x12:32/--
    var x13 = decode24(n, 46).toLong() shl 4 and M32L // x13:28/--
    var x14 = decode32(n, 49).toLong() and M32L // x14:32/--
    var x15 = decode24(n, 53).toLong() shl 4 and M32L // x15:28/--
    var x16 = decode32(n, 56).toLong() and M32L // x16:32/--
    var x17 = decode24(n, 60).toLong() shl 4 and M32L // x17:28/--
    val x18: Long = n[63].toLong() and M08L // x18:08/--

    val t: Long
    x09 -= x18 * L0 // x09:34/28
    x10 -= x18 * L1 // x10:33/30
    x11 -= x18 * L2 // x11:35/28
    x12 -= x18 * L3 // x12:32/31
    x13 -= x18 * L4 // x13:28/21
    x17 += x16 shr 28
    x16 = x16 and M28L // x17:28/--, x16:28/--
    x08 -= x17 * L0 // x08:54/32
    x09 -= x17 * L1 // x09:52/51
    x10 -= x17 * L2 // x10:55/34
    x11 -= x17 * L3 // x11:51/36
    x12 -= x17 * L4 // x12:41/--
    x07 -= x16 * L0 // x07:54/28
    x08 -= x16 * L1 // x08:54/53
    x09 -= x16 * L2 // x09:55/53
    x10 -= x16 * L3 // x10:55/52
    x11 -= x16 * L4 // x11:51/41
    x15 += x14 shr 28
    x14 = x14 and M28L // x15:28/--, x14:28/--
    x06 -= x15 * L0 // x06:54/32
    x07 -= x15 * L1 // x07:54/53
    x08 -= x15 * L2 // x08:56/--
    x09 -= x15 * L3 // x09:55/54
    x10 -= x15 * L4 // x10:55/53
    x05 -= x14 * L0 // x05:54/28
    x06 -= x14 * L1 // x06:54/53
    x07 -= x14 * L2 // x07:56/--
    x08 -= x14 * L3 // x08:56/51
    x09 -= x14 * L4 // x09:56/--
    x13 += x12 shr 28
    x12 = x12 and M28L // x13:28/22, x12:28/--
    x04 -= x13 * L0 // x04:54/49
    x05 -= x13 * L1 // x05:54/53
    x06 -= x13 * L2 // x06:56/--
    x07 -= x13 * L3 // x07:56/52
    x08 -= x13 * L4 // x08:56/52
    x12 += x11 shr 28
    x11 = x11 and M28L // x12:28/24, x11:28/--
    x03 -= x12 * L0 // x03:54/49
    x04 -= x12 * L1 // x04:54/51
    x05 -= x12 * L2 // x05:56/--
    x06 -= x12 * L3 // x06:56/52
    x07 -= x12 * L4 // x07:56/53
    x11 += x10 shr 28
    x10 = x10 and M28L // x11:29/--, x10:28/--
    x02 -= x11 * L0 // x02:55/32
    x03 -= x11 * L1 // x03:55/--
    x04 -= x11 * L2 // x04:56/55
    x05 -= x11 * L3 // x05:56/52
    x06 -= x11 * L4 // x06:56/53
    x10 += x09 shr 28
    x09 = x09 and M28L // x10:29/--, x09:28/--
    x01 -= x10 * L0 // x01:55/28
    x02 -= x10 * L1 // x02:55/54
    x03 -= x10 * L2 // x03:56/55
    x04 -= x10 * L3 // x04:57/--
    x05 -= x10 * L4 // x05:56/53
    x08 += x07 shr 28
    x07 = x07 and M28L // x08:56/53, x07:28/--
    x09 += x08 shr 28
    x08 = x08 and M28L // x09:29/25, x08:28/--
    t = x08 ushr 27
    x09 += t // x09:29/26
    x00 -= x09 * L0 // x00:55/53
    x01 -= x09 * L1 // x01:55/54
    x02 -= x09 * L2 // x02:57/--
    x03 -= x09 * L3 // x03:57/--
    x04 -= x09 * L4 // x04:57/42
    x01 += x00 shr 28
    x00 = x00 and M28L
    x02 += x01 shr 28
    x01 = x01 and M28L
    x03 += x02 shr 28
    x02 = x02 and M28L
    x04 += x03 shr 28
    x03 = x03 and M28L
    x05 += x04 shr 28
    x04 = x04 and M28L
    x06 += x05 shr 28
    x05 = x05 and M28L
    x07 += x06 shr 28
    x06 = x06 and M28L
    x08 += x07 shr 28
    x07 = x07 and M28L
    x09 = x08 shr 28
    x08 = x08 and M28L
    x09 -= t
    x00 += x09 and L0.toLong()
    x01 += x09 and L1.toLong()
    x02 += x09 and L2.toLong()
    x03 += x09 and L3.toLong()
    x04 += x09 and L4.toLong()
    x01 += x00 shr 28
    x00 = x00 and M28L
    x02 += x01 shr 28
    x01 = x01 and M28L
    x03 += x02 shr 28
    x02 = x02 and M28L
    x04 += x03 shr 28
    x03 = x03 and M28L
    x05 += x04 shr 28
    x04 = x04 and M28L
    x06 += x05 shr 28
    x05 = x05 and M28L
    x07 += x06 shr 28
    x06 = x06 and M28L
    x08 += x07 shr 28
    x07 = x07 and M28L
    val r = ByteArray(SCALAR_BYTES)
    encode56(x00 or (x01 shl 28), r, 0)
    encode56(x02 or (x03 shl 28), r, 7)
    encode56(x04 or (x05 shl 28), r, 14)
    encode56(x06 or (x07 shl 28), r, 21)
    encode32(x08.toInt(), r, 28)
    return r
  }

  private fun scalarMultBase(k: ByteArray, r: PointAccum) {
    val n = IntArray(SCALAR_INTS)
    decodeScalar(k, 0, n)

    // Recode the scalar into signed-digit form, then group comb bits in each block
    //int c1 =
    cadd(SCALAR_INTS, n[0].inv() and 1, n, L, n) //assert c1 == 0;
    //int c2 =
    shiftDownBit(SCALAR_INTS, n, 1) //assert c2 == (1 << 31);
    for (i in 0 until SCALAR_INTS) {
      n[i] = shuffle2(n[i])
    }

    val p = PointPrecomp()
    pointSetNeutral(r)
    var cOff = (PRECOMP_SPACING - 1) * PRECOMP_TEETH
    while (true) {
      for (b in 0 until PRECOMP_BLOCKS) {
        val w = n[b] ushr cOff
        val sign = w ushr PRECOMP_TEETH - 1 and 1
        val abs = w xor -sign and PRECOMP_MASK
        pointLookup(b, abs, p)
        X25519Field.cswap(sign, p.ypx_h, p.ymx_h)
        X25519Field.cnegate(sign, p.xyd)
        pointAddPrecomp(p, r)
      }
      if (PRECOMP_TEETH.let { cOff -= it; cOff } < 0) {
        break
      }
      pointDouble(r)
    }
  }

  private fun scalarMultBaseEncoded(k: ByteArray, r: ByteArray, rOff: Int) {
    val p = PointAccum()
    scalarMultBase(k, p)
    if (0 == encodePoint(p, r, rOff)) {
      throw Error("scalarMultBaseEncoded error")
    }
  }

  /**
   * NOTE: Only for use by X25519
   */
  internal fun scalarMultBaseYZ(k: ByteArray, kOff: Int, y: IntArray, z: IntArray) {
    val n = ByteArray(SCALAR_BYTES)
    pruneScalar(k, kOff, n)
    val p = PointAccum()
    scalarMultBase(n, p)
    if (0 == checkPoint(p.x, p.y, p.z)) {
      throw Error("scalarMultBaseYZ error")
    }
    X25519Field.copy(p.y, 0, y, 0)
    X25519Field.copy(p.z, 0, z, 0)
  }

  private fun scalarMultStrausVar(nb: IntArray, np: IntArray, p: PointAffine, r: PointAccum) {
    val width = 5
    val ws_b = getWnafVar(nb, WNAF_WIDTH_BASE)
    val ws_p = getWnafVar(np, width)

    val tp = pointPrecomputeVar(pointCopy(p), 1 shl width - 2)
    pointSetNeutral(r)
    var bit = 252
    while (true) {
      val wb = ws_b[bit].toInt()
      if (wb != 0) {
        val sign = wb shr 31
        val index = wb xor sign ushr 1
        pointAddVar(sign != 0, precompBaseTable[index], r)
      }
      val wp = ws_p[bit].toInt()
      if (wp != 0) {
        val sign = wp shr 31
        val index = wp xor sign ushr 1
        pointAddVar(sign != 0, tp[index], r)
      }
      if (--bit < 0) {
        break
      }
      pointDouble(r)
    }
  }

  private fun shuffle2(x: Int): Int {
    // "shuffle" (twice) low half to even bits and high half to odd bits
    @Suppress("NAME_SHADOWING") var x = x
    x = bitPermuteStep(x, 0x00AA00AA, 7)
    x = bitPermuteStep(x, 0x0000CCCC, 14)
    x = bitPermuteStep(x, 0x00F000F0, 4)
    x = bitPermuteStep(x, 0x0000FF00, 8)
    return x
  }

  private fun bitPermuteStep(x: Int, m: Int, s: Int): Int {
    val t = x xor (x ushr s) and m
    return t xor (t shl s) xor x
  }

  private fun cadd(len: Int, mask: Int, x: IntArray, y: IntArray, z: IntArray): Int {
    val MASK = -(mask.toLong() and 1) and M
    var c: Long = 0
    for (i in 0 until len) {
      c += (x[i].toLong() and M) + (y[i].toLong() and MASK)
      z[i] = c.toInt()
      c = c ushr 32
    }
    return c.toInt()
  }

  private fun shiftDownBit(len: Int, z: IntArray, c: Int): Int {
    @Suppress("NAME_SHADOWING") var c = c
    var i = len
    while (--i >= 0) {
      val next = z[i]
      z[i] = next ushr 1 or (c shl 31)
      c = next
    }
    return c shl 31
  }

  private fun gte(x: IntArray, y: IntArray): Boolean {
    for (i in 7 downTo 0) {
      val x_i = x[i] xor Int.MIN_VALUE
      val y_i = y[i] xor Int.MIN_VALUE
      if (x_i < y_i) return false
      if (x_i > y_i) return true
    }
    return true
  }

  private fun mulAddTo(x: IntArray, y: IntArray, zz: IntArray): Int {
    val y_0 = y[0].toLong() and M
    val y_1 = y[1].toLong() and M
    val y_2 = y[2].toLong() and M
    val y_3 = y[3].toLong() and M
    val y_4 = y[4].toLong() and M
    val y_5 = y[5].toLong() and M
    val y_6 = y[6].toLong() and M
    val y_7 = y[7].toLong() and M

    var zc: Long = 0
    for (i in 0..7) {
      var c: Long = 0
      val x_i = x[i].toLong() and M
      c += x_i * y_0 + (zz[i + 0].toLong() and M)
      zz[i + 0] = c.toInt()
      c = c ushr 32
      c += x_i * y_1 + (zz[i + 1].toLong() and M)
      zz[i + 1] = c.toInt()
      c = c ushr 32
      c += x_i * y_2 + (zz[i + 2].toLong() and M)
      zz[i + 2] = c.toInt()
      c = c ushr 32
      c += x_i * y_3 + (zz[i + 3].toLong() and M)
      zz[i + 3] = c.toInt()
      c = c ushr 32
      c += x_i * y_4 + (zz[i + 4].toLong() and M)
      zz[i + 4] = c.toInt()
      c = c ushr 32
      c += x_i * y_5 + (zz[i + 5].toLong() and M)
      zz[i + 5] = c.toInt()
      c = c ushr 32
      c += x_i * y_6 + (zz[i + 6].toLong() and M)
      zz[i + 6] = c.toInt()
      c = c ushr 32
      c += x_i * y_7 + (zz[i + 7].toLong() and M)
      zz[i + 7] = c.toInt()
      c = c ushr 32
      zc += c + zz[i + 8].toLong() and M
      zz[i + 8] = zc.toInt()
      zc = zc ushr 32
    }
    return zc.toInt()
  }

  private class PointAccum {
    var x = X25519Field.create()
    var y = X25519Field.create()
    var z = X25519Field.create()
    var u = X25519Field.create()
    var v = X25519Field.create()
  }

  private class PointAffine {
    var x = X25519Field.create()
    var y = X25519Field.create()
  }

  private class PointExt {
    var x = X25519Field.create()
    var y = X25519Field.create()
    var z = X25519Field.create()
    var t = X25519Field.create()
  }

  private class PointPrecomp {
    var ypx_h = X25519Field.create()
    var ymx_h = X25519Field.create()
    var xyd = X25519Field.create()
  }
}
