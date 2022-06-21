package diglol.crypto

import cocoapods.Argon2.Argon2KeyDerivator
import cocoapods.Argon2.Argon2Type
import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toNSData
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.Foundation.NSError

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
    V13
  }

  actual enum class Type {
    I,
    D,
    ID;

    fun type(): Argon2Type {
      return when (this) {
        I -> Argon2Type.Argon2i
        D -> Argon2Type.Argon2d
        ID -> Argon2Type.Argon2id
      }
    }
  }

  init {
    checkParams()
  }

  actual override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray =
    memScoped {
      checkArgon2Salt(salt)
      val errorPtr = alloc<ObjCObjectVar<NSError?>>().ptr
      val result = Argon2KeyDerivator.makeKeyOfLength(
        hashSize.toUInt(),
        type.type(),
        iterations.toUInt(),
        memory.toUInt(),
        parallelism.toUInt(),
        password.toNSData(),
        salt.toNSData(),
        errorPtr
      )
      val nsError = errorPtr.pointed.value
      if (nsError == null) {
        return result!!.toByteArray()
      } else {
        throw Error("Argon2 ${type.name} error: ${nsError.code}")
      }
    }
}
