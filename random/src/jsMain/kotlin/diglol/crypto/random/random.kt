package diglol.crypto.random

import kotlin.math.abs
import kotlin.math.absoluteValue
import kotlinx.browser.window
import org.khronos.webgl.Int32Array
import org.khronos.webgl.get

private val crypto = window.asDynamic().crypto
private const val jsNextBytesMaxSize = 65536

actual fun nextInt(bound: Int): Int {
  checkBound(bound)
  val value = Int32Array(1)
  crypto.getRandomValues(value)
  return abs(value[0].absoluteValue % bound)
}

actual fun nextBytes(size: Int): ByteArray {
  val result = ByteArray(size)
  val times = size / jsNextBytesMaxSize
  val remainder = size % jsNextBytesMaxSize
  var offset = 0
  repeat(times) {
    val data = ByteArray(jsNextBytesMaxSize)
    crypto.getRandomValues(data)
    data.copyInto(result, offset, 0, jsNextBytesMaxSize)
    offset = times * jsNextBytesMaxSize
  }
  if (remainder != 0) {
    val data = ByteArray(remainder)
    crypto.getRandomValues(data)
    data.copyInto(result, offset, 0, remainder)
  }
  return result
}
