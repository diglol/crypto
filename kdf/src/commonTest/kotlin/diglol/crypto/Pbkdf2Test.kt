package diglol.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.test.runTest

class Pbkdf2Test {
  @Suppress("ArrayInDataClass")
  private data class Sample(
    val password: String,
    val salt: String,
    val iterations: Int,
    val result: ByteArray,
  )

  // http://tools.ietf.org/html/rfc6070
  private val hmacSha1Samples = listOf(
    Sample(
      "password", "salt", 1,
      byteArrayOf(
        0x0c, 0x60, 0xc8.toByte(), 0x0f, 0x96.toByte(), 0x1f, 0x0e, 0x71,
        0xf3.toByte(), 0xa9.toByte(), 0xb5.toByte(), 0x24, 0xaf.toByte(), 0x60, 0x12, 0x06,
        0x2f, 0xe0.toByte(), 0x37, 0xa6.toByte()
      )
    ),
    Sample(
      "password", "salt", 2,
      byteArrayOf(
        0xea.toByte(), 0x6c, 0x01, 0x4d, 0xc7.toByte(), 0x2d, 0x6f, 0x8c.toByte(),
        0xcd.toByte(), 0x1e, 0xd9.toByte(), 0x2a, 0xce.toByte(), 0x1d, 0x41, 0xf0.toByte(),
        0xd8.toByte(), 0xde.toByte(), 0x89.toByte(), 0x57,
      )
    ),
    Sample(
      "password", "salt", 4096,
      byteArrayOf(
        0x4b, 0x00, 0x79, 0x01, 0xb7.toByte(), 0x65, 0x48, 0x9a.toByte(),
        0xbe.toByte(), 0xad.toByte(), 0x49, 0xd9.toByte(), 0x26, 0xf7.toByte(), 0x21, 0xd0.toByte(),
        0x65, 0xa4.toByte(), 0x29, 0xc1.toByte(),
      )
    )
  )

  // http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
  private val hmacSha256Samples = listOf(
    Sample(
      "password", "salt", 1,
      byteArrayOf(
        0x12, 0x0f, 0xb6.toByte(), 0xcf.toByte(), 0xfc.toByte(), 0xf8.toByte(), 0xb3.toByte(), 0x2c,
        0x43, 0xe7.toByte(), 0x22, 0x52, 0x56, 0xc4.toByte(), 0xf8.toByte(), 0x37,
        0xa8.toByte(), 0x65, 0x48, 0xc9.toByte(), 0x2c, 0xcc.toByte(), 0x35, 0x48,
        0x08, 0x05, 0x98.toByte(), 0x7c, 0xb7.toByte(), 0x0b, 0xe1.toByte(), 0x7b
      )
    ),
    Sample(
      "password", "salt", 2,
      byteArrayOf(
        0xae.toByte(), 0x4d, 0x0c, 0x95.toByte(), 0xaf.toByte(), 0x6b, 0x46, 0xd3.toByte(),
        0x2d, 0x0a, 0xdf.toByte(), 0xf9.toByte(), 0x28, 0xf0.toByte(), 0x6d, 0xd0.toByte(),
        0x2a, 0x30, 0x3f, 0x8e.toByte(), 0xf3.toByte(), 0xc2.toByte(), 0x51, 0xdf.toByte(),
        0xd6.toByte(), 0xe2.toByte(), 0xd8.toByte(), 0x5a, 0x95.toByte(), 0x47, 0x4c, 0x43
      )
    ),
    Sample(
      "password", "salt", 4096,
      byteArrayOf(
        0xc5.toByte(), 0xe4.toByte(), 0x78, 0xd5.toByte(), 0x92.toByte(), 0x88.toByte(),
        0xc8.toByte(), 0x41, 0xaa.toByte(), 0x53, 0x0d, 0xb6.toByte(), 0x84.toByte(),
        0x5c, 0x4c, 0x8d.toByte(), 0x96.toByte(), 0x28, 0x93.toByte(), 0xa0.toByte(),
        0x01, 0xce.toByte(), 0x4e, 0x11, 0xa4.toByte(), 0x96.toByte(), 0x38, 0x73,
        0xaa.toByte(), 0x98.toByte(), 0x13, 0x4a
      )
    )
  )

  @Test
  fun hmacSha1() = runTest {
    hmacSha1Samples.forEachIndexed { index, (password, salt, iterations, result) ->
      val pbkdf2 = Pbkdf2(Hmac.Type.SHA1, iterations)
      val actual = pbkdf2.deriveKey(password.encodeToByteArray(), salt.encodeToByteArray())
      assertContentEquals(result, actual, index.toString())
    }
  }

  @Test
  fun hmacSha256() = runTest {
    hmacSha256Samples.forEachIndexed { index, (password, salt, iterations, result) ->
      val pbkdf2 = Pbkdf2(Hmac.Type.SHA256, iterations)
      val actual = pbkdf2.deriveKey(password.encodeToByteArray(), salt.encodeToByteArray())
      assertContentEquals(result, actual, index.toString())
    }
  }
}
