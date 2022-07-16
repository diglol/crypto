package diglol.crypto

import diglol.crypto.internal.ed25519_CreatePublicKey
import diglol.crypto.internal.ed25519_SignMessage
import diglol.crypto.internal.ed25519_VerifySignature
import kotlinx.cinterop.convert
import kotlinx.cinterop.cstr
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import kotlinx.cinterop.reinterpret
import platform.posix.NULL

// https://datatracker.ietf.org/doc/html/rfc8032
actual object Ed25519 : Dsa {
  actual val KEY_SIZE: Int = ED25519_KEY_SIZE
  actual val SIGN_SIZE: Int = ED25519_SIGN_SIZE

  actual override suspend fun generateKeyPair(): KeyPair = generateKeyPair(generatePrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkPrivateKey(privateKey)
    val publicKey = ByteArray(KEY_SIZE)
    memScoped {
      ed25519_CreatePublicKey(
        publicKey.refTo(0).getPointer(memScope).reinterpret(),
        NULL,
        privateKey.refTo(0).getPointer(memScope).reinterpret(),
      )
    }
    return KeyPair(publicKey, privateKey)
  }

  actual override suspend fun sign(privateKey: ByteArray, data: ByteArray): ByteArray =
    sign(generateKeyPair(privateKey), data)

  actual suspend fun sign(keyPair: KeyPair, data: ByteArray): ByteArray {
    val signature = ByteArray(SIGN_SIZE)
    memScoped {
      ed25519_SignMessage(
        signature.refTo(0).getPointer(memScope).reinterpret(),
        (keyPair.privateKey + keyPair.publicKey).refTo(0).getPointer(memScope).reinterpret(),
        NULL,
        (if (data.isEmpty()) "".cstr else data.refTo(0)).getPointer(memScope).reinterpret(),
        data.size.convert()
      )
    }
    return signature
  }

  actual override suspend fun verify(
    signature: ByteArray,
    publicKey: ByteArray,
    data: ByteArray
  ): Boolean {
    checkSignature(signature)
    checkPublicKey(publicKey)
    memScoped {
      return ed25519_VerifySignature(
        signature.refTo(0).getPointer(memScope).reinterpret(),
        publicKey.refTo(0).getPointer(memScope).reinterpret(),
        (if (data.isEmpty()) "".cstr else data.refTo(0)).getPointer(memScope).reinterpret(),
        data.size.convert()
      ) == 1
    }
  }
}
