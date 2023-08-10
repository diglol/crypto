package diglol.crypto

import diglol.crypto.internal.curve25519_dh_CalculatePublicKey_fast
import diglol.crypto.internal.curve25519_dh_CreateSharedKey
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.refTo

// https://datatracker.ietf.org/doc/html/rfc7748
actual object X25519 : Dh {
  actual val KEY_SIZE: Int = X25519_KEY_SIZE

  actual override suspend fun generateKeyPair(): KeyPair = generateKeyPair(generatePrivateKey())

  @Suppress("UNCHECKED_CAST")
  @OptIn(ExperimentalForeignApi::class)
  actual override suspend fun generateKeyPair(privateKey: ByteArray): KeyPair {
    checkPrivateKey(privateKey)
    val publicKey = ByteArray(KEY_SIZE)
    curve25519_dh_CalculatePublicKey_fast(
      publicKey.refTo(0) as CValuesRef<UByteVar>,
      privateKey.refTo(0) as CValuesRef<UByteVar>
    )
    return KeyPair(publicKey, privateKey)
  }

  @Suppress("UNCHECKED_CAST")
  @OptIn(ExperimentalForeignApi::class)
  actual override suspend fun compute(privateKey: ByteArray, peersPublicKey: ByteArray): ByteArray {
    checkPrivateKey(privateKey)
    checkPublicKey(peersPublicKey)
    val sharedKey = ByteArray(KEY_SIZE)
    curve25519_dh_CreateSharedKey(
      sharedKey.refTo(0) as CValuesRef<UByteVar>,
      peersPublicKey.refTo(0) as CValuesRef<UByteVar>,
      privateKey.refTo(0) as CValuesRef<UByteVar>
    )
    return sharedKey
  }
}
