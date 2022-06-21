package diglol.crypto

// https://datatracker.ietf.org/doc/rfc9106/
expect class Argon2(
  version: Version,
  type: Type,
  iterations: Int,
  memory: Int,
  parallelism: Int,
  hashSize: Int,
) : Kdf {
  internal val version: Version
  internal val type: Type
  internal val iterations: Int
  internal val memory: Int
  internal val parallelism: Int
  internal val hashSize: Int

  enum class Version {
    V10,
    V13
  }

  enum class Type {
    I,
    D,
    ID
  }

  override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray
}

internal fun Argon2.checkParams() {
  if (iterations == 0) {
    throw Error("Iterations too small")
  }
  if (memory < 16) {
    throw Error("Memory too small")
  }
  if (parallelism == 0) {
    throw Error("Parallelism too small")
  }
  if (hashSize == 0) {
    throw Error("Hash size too small")
  }
}

internal fun checkArgon2Salt(salt: ByteArray) {
  if (salt.size < 8) {
    throw Error("Invalid salt size")
  }
}
