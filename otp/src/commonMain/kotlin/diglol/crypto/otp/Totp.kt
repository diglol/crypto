package diglol.crypto.otp

import diglol.crypto.Hmac
import kotlinx.datetime.Clock

// https://datatracker.ietf.org/doc/html/rfc6238
class Totp(
  val hmacType: Hmac.Type,
  val hmacKey: ByteArray,
  val period: Int = 30, // Second
  override val codeLength: Int = 6,
  override val issuer: String = "",
  override val accountName: String = ""
) : Otp(hmacType, hmacKey, codeLength, issuer, accountName) {

  suspend fun generate(): String =
    super.generate(Clock.System.now().toEpochMilliseconds() / (period * 1000))

  suspend fun verify(code: String): Boolean = super.verify(
    code, Clock.System.now().toEpochMilliseconds() / (period * 1000)
  )

  override fun toUriString(): String = buildString {
    appendCommon(hmacType, hmacKey, "totp", issuer, accountName)
    append("&period=$period")
  }
}

