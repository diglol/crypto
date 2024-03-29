package diglol.crypto.internal

import org.khronos.webgl.Int8Array
import org.khronos.webgl.Uint8Array

val isBrowser = js("typeof window !== 'undefined'") as Boolean

val crypto: dynamic
  get() = if (isBrowser) {
    js("crypto")
  } else {
    js("require('crypto').webcrypto")
  }

val subtle: dynamic get() = crypto.subtle

@Suppress("NOTHING_TO_INLINE")
fun ByteArray.toUint8Array(): Uint8Array = Uint8Array(unsafeCast<Int8Array>().buffer)

fun Uint8Array.toByteArray(): ByteArray = Int8Array(buffer).unsafeCast<ByteArray>()
