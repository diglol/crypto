package diglol.crypto

import diglol.crypto.internal.ARGON2_OK
import diglol.crypto.internal.ARGON2_VERSION_10
import diglol.crypto.internal.ARGON2_VERSION_13
import diglol.crypto.internal.Argon2_d
import diglol.crypto.internal.Argon2_i
import diglol.crypto.internal.Argon2_id
import diglol.crypto.internal.Argon2_type
import diglol.crypto.internal.Argon2_version
import diglol.crypto.internal.argon2_context
import diglol.crypto.internal.argon2_ctx
import kotlinx.cinterop.cValue
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import kotlinx.cinterop.reinterpret

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

    fun version(): Argon2_version {
      return when (this) {
        V10 -> ARGON2_VERSION_10
        V13 -> ARGON2_VERSION_13
      }
    }
  }

  actual enum class Type {
    I,
    D,
    ID;

    fun type(): Argon2_type {
      return when (this) {
        I -> Argon2_i
        D -> Argon2_d
        ID -> Argon2_id
      }
    }
  }

  init {
    checkParams()
  }

  actual override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray =
    memScoped {
      checkArgon2Salt(salt)
      val result = ByteArray(hashSize)
      val context = cValue<argon2_context> {
        out = result.refTo(0).getPointer(memScope).reinterpret()
        outlen = hashSize.convert()

        pwd = password.refTo(0).getPointer(memScope).reinterpret()
        pwdlen = password.size.convert()

        this.salt = salt.refTo(0).getPointer(memScope).reinterpret()
        saltlen = salt.size.convert()

        t_cost = iterations.convert()
        m_cost = memory.convert()

        lanes = parallelism.convert()
        threads = parallelism.convert()

        version = this@Argon2.version.version()
      }
      val errorCode = argon2_ctx(context, type.type())
      if (errorCode == ARGON2_OK) {
        return result
      } else {
        throw Error("Argon2 ${type.name} error: $errorCode")
      }
    }
}
