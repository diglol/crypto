package diglol.crypto

import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toUint8Array
import diglol.encoding.decodeBase64ToBytes
import kotlin.js.Promise
import kotlinx.browser.window
import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array

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

    fun type(): Int = when (this) {
      I -> 1
      D -> 0
      ID -> 2
    }
  }

  init {
    checkParams()
    window.asDynamic().loadArgon2WasmBinary = fun(): Promise<Uint8Array> {
      return WasmFeatureDetect.simd().then {
        if (it) argon2SimdWasm else argon2Wasm
      }.then {
        it.decodeBase64ToBytes()!!.toUint8Array()
      }
    }
  }

  actual override suspend fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray {
    checkArgon2Salt(salt)
    val params = js("{}")
    params["pass"] = password.toUint8Array()
    params["salt"] = salt.toUint8Array()
    params["time"] = iterations
    params["mem"] = memory
    params["hashLen"] = hashSize
    params["parallelism"] = parallelism
    params["type"] = type.type()
    val result = Argon2Js.hash(params).await()
    return result.hash.unsafeCast<Uint8Array>().toByteArray()
  }
}

@JsModule("wasm-feature-detect")
@JsNonModule
internal external object WasmFeatureDetect {
  fun simd(): Promise<Boolean>
}

@JsModule("argon2-browser/dist/argon2.wasm")
@JsNonModule
internal external val argon2Wasm: String

@JsModule("argon2-browser/dist/argon2-simd.wasm")
@JsNonModule
internal external val argon2SimdWasm: String

@JsModule("argon2-browser")
@JsNonModule
internal external object Argon2Js {
  fun hash(params: dynamic): Promise<dynamic>
}
