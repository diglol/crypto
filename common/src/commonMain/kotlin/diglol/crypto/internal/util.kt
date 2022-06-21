package diglol.crypto.internal

import kotlin.native.concurrent.SharedImmutable

@SharedImmutable
val emptyBytes: ByteArray = ByteArray(0)

fun ByteArray.selfOrCopyOf(newSize: Int): ByteArray = if (size == newSize) this else copyOf(newSize)

fun ByteArray.plusByteArrays(vararg byteArrays: ByteArray): ByteArray {
  val outSize = byteArrays.fold(size) { count, byteArray -> count + byteArray.size }
  val out = ByteArray(outSize)
  copyInto(out, 0, 0, size)
  var offset = size
  for (byteArray in byteArrays) {
    byteArray.copyInto(out, offset, 0, byteArray.size)
    offset += byteArray.size
  }
  return out
}

fun ByteArray.toInt(isBigEndian: Boolean = true): Int? {
  if (this.size != 4) return null
  return (this[0].toInt() and 0xff shl if (isBigEndian) 24 else 0) or
    (this[1].toInt() and 0xff shl if (isBigEndian) 16 else 8) or
    (this[2].toInt() and 0xff shl if (isBigEndian) 8 else 16) or
    (this[3].toInt() and 0xff shl if (isBigEndian) 0 else 24)
}

fun Int.toByteArray(isBigEndian: Boolean = true): ByteArray = byteArrayOf(
  ((this shr if (isBigEndian) 24 else 0 and 0xff).toByte()),
  ((this shr if (isBigEndian) 16 else 8 and 0xff).toByte()),
  ((this shr if (isBigEndian) 8 else 16 and 0xff).toByte()),
  ((this shr if (isBigEndian) 0 else 24 and 0xff).toByte())
)

fun ByteArray.toLong(isBigEndian: Boolean = true): Long? = if (this.size != 8) null else
  (this[0].toLong() and 0xff shl if (isBigEndian) 56 else 0) or
    (this[1].toLong() and 0xff shl if (isBigEndian) 48 else 8) or
    (this[2].toLong() and 0xff shl if (isBigEndian) 40 else 16) or
    (this[3].toLong() and 0xff shl if (isBigEndian) 32 else 24) or
    (this[4].toLong() and 0xff shl if (isBigEndian) 24 else 32) or
    (this[5].toLong() and 0xff shl if (isBigEndian) 16 else 40) or
    (this[6].toLong() and 0xff shl if (isBigEndian) 8 else 48) or
    (this[7].toLong() and 0xff shl if (isBigEndian) 0 else 56)

fun Long.toByteArray(isBigEndian: Boolean = true): ByteArray = byteArrayOf(
  ((this shr if (isBigEndian) 56 else 0 and 0xff).toByte()),
  ((this shr if (isBigEndian) 48 else 8 and 0xff).toByte()),
  ((this shr if (isBigEndian) 40 else 16 and 0xff).toByte()),
  ((this shr if (isBigEndian) 32 else 24 and 0xff).toByte()),
  ((this shr if (isBigEndian) 24 else 32 and 0xff).toByte()),
  ((this shr if (isBigEndian) 16 else 40 and 0xff).toByte()),
  ((this shr if (isBigEndian) 8 else 48 and 0xff).toByte()),
  ((this shr if (isBigEndian) 0 else 56 and 0xff).toByte())
)
