package diglol.crypto

// https://datatracker.ietf.org/doc/html/rfc6070
expect class Pbkdf2(hmacType: Hmac.Type, iterations: Int, keySize: Int = hmacType.size()) : Kdf {
  internal val hmacType: Hmac.Type
  internal val iterations: Int
  internal val keySize: Int

  override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray
}

internal fun Pbkdf2.checkParams() {
  if (iterations == 0) {
    throw Error("Iterations too small")
  }
  if (keySize == 0) {
    throw Error("Invalid key size")
  }
}

internal fun checkPbkdf2Salt(salt: ByteArray) {
  if (salt.isEmpty()) {
    throw Error("Invalid salt size")
  }
}
