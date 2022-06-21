package diglol.crypto

import diglol.encoding.decodeHexToBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.test.runTest

class X25519Test {
  @Suppress("ArrayInDataClass")
  private data class Sample(
    val keyPair1: KeyPair,
    val keyPair2: KeyPair,
    val sharedKey: ByteArray
  )

  // https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
  private val x25519Samples = listOf(
    Sample(
      KeyPair(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a".decodeHexToBytes()!!,
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".decodeHexToBytes()!!
      ),
      KeyPair(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f".decodeHexToBytes()!!,
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb".decodeHexToBytes()!!
      ),
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742".decodeHexToBytes()!!
    )
  )

  @Test
  fun generateKeyPairWithPrivateKey() = runTest {
    x25519Samples.forEachIndexed { index, (keyPair1, keyPair2, sharedKey) ->
      assertContentEquals(
        keyPair1.publicKey,
        X25519.generateKeyPair(keyPair1.privateKey).publicKey,
        index.toString()
      )
      assertContentEquals(
        keyPair2.publicKey,
        X25519.generateKeyPair(keyPair2.privateKey).publicKey,
        index.toString()
      )
    }
  }

  @Test
  fun compute() = runTest {
    x25519Samples.forEachIndexed { index, (keyPair1, keyPair2, sharedKey) ->
      assertContentEquals(
        sharedKey,
        X25519.compute(keyPair1.privateKey, keyPair2.publicKey),
        index.toString()
      )
      assertContentEquals(
        sharedKey,
        X25519.compute(keyPair2.privateKey, keyPair1.publicKey),
        index.toString()
      )
    }
  }
}
