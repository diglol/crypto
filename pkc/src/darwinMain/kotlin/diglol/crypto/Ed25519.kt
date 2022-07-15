package diglol.crypto

import diglol.crypto.internal.Ed25519 as DarwinEd25519
import diglol.crypto.internal.KeyPair as DarwinKeyPair
import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toNSData

internal fun DarwinKeyPair.toKeyPair(): KeyPair =
  KeyPair(publicKey()!!.toByteArray(), privateKey()!!.toByteArray())

// https://datatracker.ietf.org/doc/html/rfc8032
actual object Ed25519 : Dsa {
  actual val KEY_SIZE: Int = ED25519_KEY_SIZE
  actual val SIGN_SIZE: Int = ED25519_SIGN_SIZE

  actual override suspend fun generateKeyPair(): KeyPair = generateKeyPair(generatePrivateKey())

  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkPrivateKey(privateKey)
    return DarwinEd25519.generateKeyPairWithPrivateKey(privateKey.toNSData())!!.toKeyPair()
  }

  actual override suspend fun sign(privateKey: ByteArray, data: ByteArray): ByteArray =
    DarwinEd25519.signWithPrivateKey(privateKey.toNSData(), data.toNSData())!!.toByteArray()

  actual suspend fun sign(keyPair: KeyPair, data: ByteArray): ByteArray =
    DarwinEd25519.signWithPrivateKey(keyPair.privateKey.toNSData(), data.toNSData())!!.toByteArray()

  actual override suspend fun verify(
    signature: ByteArray,
    publicKey: ByteArray,
    data: ByteArray
  ): Boolean {
    checkSignature(signature)
    checkPublicKey(publicKey)
    return DarwinEd25519.verifyWithSignature(
      signature.toNSData(),
      publicKey.toNSData(),
      data.toNSData()
    )
  }
}
