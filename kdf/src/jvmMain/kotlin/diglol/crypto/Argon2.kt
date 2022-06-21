package diglol.crypto

import de.mkammerer.argon2.Argon2Factory
import de.mkammerer.argon2.Argon2Factory.Argon2Types
import de.mkammerer.argon2.Argon2Version

// https://datatracker.ietf.org/doc/rfc9106/
actual class Argon2 actual constructor(
  internal actual val version: Version,
  internal actual val type: Type,
  internal actual val iterations: Int,
  internal actual val memory: Int,
  internal actual val parallelism: Int,
  internal actual val hashSize: Int
) : Kdf {
  actual enum class Version {
    V10,
    V13;

    fun version(): Argon2Version {
      return when (this) {
        V10 -> Argon2Version.V10
        V13 -> Argon2Version.V13
      }
    }
  }

  actual enum class Type {
    I,
    D,
    ID;

    fun type(): Argon2Types {
      return when (this) {
        I -> Argon2Types.ARGON2i
        D -> Argon2Types.ARGON2d
        ID -> Argon2Types.ARGON2id
      }
    }
  }

  init {
    checkParams()
  }

  actual override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray {
    checkArgon2Salt(salt)
    return Argon2Factory.createAdvanced(type.type())
      .pbkdf(iterations, memory, parallelism, password, salt, hashSize)
  }
}
