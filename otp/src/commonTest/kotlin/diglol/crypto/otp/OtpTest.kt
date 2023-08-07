package diglol.crypto.otp

import diglol.crypto.otp.Otp.Companion.toOtp
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class OtpTest {

  @Test
  fun testToOtp() = runTest {
    assertEquals("11".toOtp(), null)
    assertEquals("otpauth".toOtp(), null)
    assertEquals("otpauth://totp/".toOtp(), null)
  }
}
