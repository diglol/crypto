package diglol.crypto.random

import diglol.crypto.internal.toInt
import kotlin.math.abs

internal inline fun commonNextInt(bound: Int): Int {
  checkBound(bound)
  return abs(nextBytes(4).toInt()!!) % bound
}
