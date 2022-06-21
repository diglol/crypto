package diglol.crypto.otp

import diglol.crypto.Hmac
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class TotpTest {
  private val hotpSamples = listOf(
    Triple(Hmac.Type.SHA1, 59L, "94287082"),
    Triple(Hmac.Type.SHA256, 59L, "46119246"),
    Triple(Hmac.Type.SHA512, 59L, "90693936"),
    Triple(Hmac.Type.SHA1, 1111111109L, "07081804"),
    Triple(Hmac.Type.SHA256, 1111111109L, "68084774"),
    Triple(Hmac.Type.SHA512, 1111111109L, "25091201"),
    Triple(Hmac.Type.SHA1, 1111111111L, "14050471"),
    Triple(Hmac.Type.SHA256, 1111111111L, "67062674"),
    Triple(Hmac.Type.SHA512, 1111111111L, "99943326"),
    Triple(Hmac.Type.SHA1, 1234567890L, "89005924"),
    Triple(Hmac.Type.SHA256, 1234567890L, "91819424"),
    Triple(Hmac.Type.SHA512, 1234567890L, "93441116"),
    Triple(Hmac.Type.SHA1, 2000000000L, "69279037"),
    Triple(Hmac.Type.SHA256, 2000000000L, "90698825"),
    Triple(Hmac.Type.SHA512, 2000000000L, "38618901"),
    Triple(Hmac.Type.SHA1, 20000000000L, "65353130"),
    Triple(Hmac.Type.SHA256, 20000000000L, "77737706"),
    Triple(Hmac.Type.SHA512, 20000000000L, "47863826"),
  )

  private fun hmacKey(hmacType: Hmac.Type) = when (hmacType) {
    Hmac.Type.SHA1 -> "12345678901234567890".encodeToByteArray()
    Hmac.Type.SHA256 -> "12345678901234567890123456789012".encodeToByteArray()
    Hmac.Type.SHA512 -> "1234567890123456789012345678901234567890123456789012345678901234".encodeToByteArray()
    else -> TODO()
  }

  @Test
  fun generate() = runTest {
    hotpSamples.forEachIndexed { index, (hmacType, counter, code) ->
      val totp = Totp(hmacType, hmacKey(hmacType), 30, 8, "Diglol", "Crypto")
      val actual = totp.generate(counter / 30)
      assertEquals(code, actual, index.toString())
    }
  }

  @Test
  fun verify() = runTest {
    hotpSamples.forEachIndexed { index, (hmacType, counter, code) ->
      val totp = Totp(hmacType, hmacKey(hmacType), 30, 8, "Diglol", "Crypto")
      assertTrue(totp.verify(code, counter / 30), index.toString())
    }
  }

  @Test
  fun toUriString() = runTest {
    val totp = Totp(Hmac.Type.SHA1, hmacKey(Hmac.Type.SHA1), 30, 8, "Diglol", "Crypto")
    val totpUriString =
      "otpauth://totp/Diglol:Crypto?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Diglol&algorithm=SHA1&digits=8&period=30"
    assertEquals(totpUriString, totp.toUriString())
    assertEquals(totpUriString, totpUriString.toOtp()?.toUriString())
  }
}
