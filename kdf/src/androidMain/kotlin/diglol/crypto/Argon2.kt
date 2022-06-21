package diglol.crypto

import org.signal.argon2.Argon2 as SignalArgon2
import org.signal.argon2.Type as Argon2Type
import org.signal.argon2.Version as Argon2Version

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

    fun type(): Argon2Type {
      return when (this) {
        I -> Argon2Type.Argon2i
        D -> Argon2Type.Argon2d
        ID -> Argon2Type.Argon2d
      }
    }
  }

  init {
    checkParams()
  }

  actual override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray {
    checkArgon2Salt(salt)
    return SignalArgon2.Builder(version.version()).type(type.type())
      .iterations(iterations)
      .memoryCostKiB(memory)
      .parallelism(parallelism)
      .hashLength(hashSize)
      .build()
      .hash(password, salt).hash
  }
}
