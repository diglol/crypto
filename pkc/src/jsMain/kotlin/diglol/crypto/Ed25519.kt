package diglol.crypto

import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toUint8Array
import kotlin.js.Promise
import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array

// https://datatracker.ietf.org/doc/html/rfc8032
actual object Ed25519 : Dsa {
  actual val KEY_SIZE: Int = ED25519_KEY_SIZE
  actual val SIGN_SIZE: Int = ED25519_SIGN_SIZE

  actual override suspend fun generateKeyPair(): KeyPair =
    generateKeyPair(generatePrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkPrivateKey(privateKey)
    val publicKey = Ed25519Js.getPublicKey(privateKey.toUint8Array()).await().toByteArray()
    return KeyPair(publicKey, privateKey)
  }

  actual override suspend fun sign(privateKey: ByteArray, data: ByteArray): ByteArray {
    val keyPair = generateKeyPair(privateKey)
    return Ed25519Js.sign(
      data.toUint8Array(), keyPair.privateKey.toUint8Array(),
      keyPair.publicKey.toUint8Array()
    ).await().toByteArray()
  }

  actual suspend fun sign(keyPair: KeyPair, data: ByteArray): ByteArray {
    return Ed25519Js.sign(
      data.toUint8Array(), keyPair.privateKey.toUint8Array(), keyPair.publicKey.toUint8Array()
    ).await().toByteArray()
  }

  actual override suspend fun verify(
    signature: ByteArray,
    publicKey: ByteArray,
    data: ByteArray
  ): Boolean {
    checkSignature(signature)
    checkPublicKey(publicKey)
    return Ed25519Js.verify(signature.toUint8Array(), data.toUint8Array(), publicKey.toUint8Array())
      .await()
  }
}

internal external object Curve25519 {
  fun scalarMultBase(privateKey: Uint8Array): Uint8Array
  fun scalarMult(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array
}

@JsModule("@robxyy/noble-ed25519")
@JsNonModule
internal external object Ed25519Js {
  val curve25519: Curve25519

  fun getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>

  fun sign(hash: Uint8Array, privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array>
  fun verify(signature: Uint8Array, hash: Uint8Array, publicKey: Uint8Array): Promise<Boolean>
}
