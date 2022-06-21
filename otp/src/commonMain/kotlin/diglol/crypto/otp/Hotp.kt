package diglol.crypto.otp

import diglol.crypto.Hmac

// https://datatracker.ietf.org/doc/html/rfc4226
class Hotp(
  val hmacType: Hmac.Type,
  val hmacKey: ByteArray,
  var counter: Long = 0L,
  override val codeLength: Int = 6,
  override val issuer: String = "",
  override val accountName: String = "",
) : Otp(hmacType, hmacKey, codeLength, issuer, accountName) {

  suspend fun generate() = super.generate(counter)

  override suspend fun generate(counter: Long): String {
    this.counter = counter
    return super.generate(counter)
  }

  override fun toUriString(): String = buildString {
    appendCommon(hmacType, hmacKey, "hotp", issuer, accountName)
    append("&counter=$counter")
  }
}
