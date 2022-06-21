package diglol.crypto.otp

import diglol.crypto.Hmac
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class HotpTest {
  // https://datatracker.ietf.org/doc/html/rfc4226#appendix-D
  private val hotp =
    Hotp(Hmac.Type.SHA1, "12345678901234567890".encodeToByteArray(), 0, 6, "Diglol", "Crypto")
  private val hotpSamples = listOf(
    Pair(0L, "755224"),
    Pair(1L, "287082"),
    Pair(2L, "359152"),
    Pair(3L, "969429"),
    Pair(4L, "338314"),
    Pair(5L, "254676"),
    Pair(6L, "287922"),
    Pair(7L, "162583"),
    Pair(8L, "399871"),
    Pair(9L, "520489"),
  )

  @Test
  fun generate() = runTest {
    hotpSamples.forEachIndexed { index, (counter, code) ->
      val actual = hotp.generate(counter)
      assertEquals(code, actual, index.toString())
    }
  }

  @Test
  fun verify() = runTest {
    hotpSamples.forEachIndexed { index, (counter, code) ->
      assertTrue(hotp.verify(code, counter), index.toString())
    }
  }

  @Test
  fun toUriString() = runTest {
    val hotpUriString =
      "otpauth://hotp/Diglol:Crypto?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Diglol&algorithm=SHA1&digits=6&counter=0"
    assertEquals(hotpUriString, hotp.toUriString())
    assertEquals(hotpUriString, hotpUriString.toOtp()?.toUriString())
  }
}
