package diglol.crypto

import diglol.crypto.internal.isBrowser
import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toUint8Array
import diglol.encoding.decodeBase64ToBytes
import kotlin.js.Promise
import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
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
    val global = js("typeof self !== 'undefined' ? self : this")
    global.loadArgon2WasmBinary = fun(): Promise<Uint8Array> {
      return WasmFeatureDetect.simd().then { simdSupported ->
        if (simdSupported) {
          js("require('argon2-browser/dist/argon2-simd.wasm')")
        } else {
          js("require('argon2-browser/dist/argon2.wasm')")
        }
      }.then { wasm: dynamic ->
        if (isBrowser) {
          val wasmString = wasm as String
          wasmString.decodeBase64ToBytes()!!.toUint8Array()
        } else {
          Uint8Array(wasm.arrayBuffer() as ArrayBuffer)
        }
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

@JsModule("argon2-browser")
@JsNonModule
internal external object Argon2Js {
  fun hash(params: dynamic): Promise<dynamic>
}
