package diglol.crypto.random

internal fun checkBound(bound: Int) {
  if (bound <= 0) {
    throw IllegalArgumentException("bound must be positive")
  }
}
