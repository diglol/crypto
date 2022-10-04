package diglol.crypto

import diglol.crypto.internal.emptyBytes
import diglol.encoding.decodeHexToBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.test.runTest

class AesCbcTest {
  @Suppress("ArrayInDataClass")
  private data class Sample(
    val key: ByteArray,
    val iv: ByteArray,
    val plaintext: ByteArray,
    val ciphertext: ByteArray
  )

  // https://datatracker.ietf.org/doc/html/rfc3602#section-4
  private val aesCbcSamples = listOf(
    Sample(
      "c286696d887c9aa0611bbb3e2025a45a".decodeHexToBytes()!!,
      "562e17996d093d28ddb3ba695a2e6f58".decodeHexToBytes()!!,
      emptyBytes,
      "d3bcd806dfdecb0a1b13d580ce51a929".decodeHexToBytes()!!,
    ),
    Sample(
      "c286696d887c9aa0611bbb3e2025a45a".decodeHexToBytes()!!,
      "562e17996d093d28ddb3ba695a2e6f58".decodeHexToBytes()!!,
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".decodeHexToBytes()!!,
      "d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1bcfd81022202366bde6dd260a15841a1".decodeHexToBytes()!!,
    ),
    Sample(
      "6c3ea0477630ce21a2ce334aa746c2cd".decodeHexToBytes()!!,
      "c782dc4c098c66cbd9cd27d825682c81".decodeHexToBytes()!!,
      "This is a 48-byte message (exactly 3 AES blocks)".encodeToByteArray(),
      "d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5021c19216bad525c8579695d83ba2684d248b3e0f2388c137102846eb06272ff".decodeHexToBytes()!!,
    ),
    Sample(
      "56e47a38c5598974bc46903dba290349".decodeHexToBytes()!!,
      "8ce82eefbea0da3c44699ed7db51b7d9".decodeHexToBytes()!!,
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf".decodeHexToBytes()!!,
      "c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da5578b8d04731041aa2d9787ca4a4fa3eef".decodeHexToBytes()!!,
    ),
  )

  @Test
  fun encrypt() = runTest {
    aesCbcSamples.forEachIndexed { index, (key, iv, plaintext, ciphertext) ->
      val aesCbc = AesCbc(key, iv)
      val actual = aesCbc.encrypt(plaintext)
      assertContentEquals(iv + ciphertext, actual, index.toString())
    }
  }

  @Test
  fun decrypt() = runTest {
    aesCbcSamples.forEachIndexed { index, (key, iv, plaintext, ciphertext) ->
      val aesCbc = AesCbc(key, iv)
      val actual = aesCbc.decrypt(iv + ciphertext)
      assertContentEquals(plaintext, actual, index.toString())
    }
  }
}
