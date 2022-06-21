package diglol.crypto.internal

import org.khronos.webgl.Int8Array
import org.khronos.webgl.Uint8Array

@Suppress("NOTHING_TO_INLINE")
fun ByteArray.toUint8Array(): Uint8Array = Uint8Array(unsafeCast<Int8Array>().buffer)

fun Uint8Array.toByteArray(): ByteArray = Int8Array(buffer).unsafeCast<ByteArray>()
