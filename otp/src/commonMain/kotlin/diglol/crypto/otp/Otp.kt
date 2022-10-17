package diglol.crypto.otp

import diglol.crypto.Hmac
import diglol.crypto.internal.toByteArray
import diglol.encoding.decodeBase32ToBytes
import diglol.encoding.encodeBase32ToString
import kotlin.experimental.and
import kotlin.jvm.JvmStatic
import kotlin.math.pow

abstract class Otp(
  hmacType: Hmac.Type,
  hmacKey: ByteArray,
  open val codeLength: Int,
  open val issuer: String,
  open val accountName: String
) {
  private val hmac = Hmac(hmacType, hmacKey)

  open suspend fun generate(counter: Long): String {
    val counterBytes = counter.toByteArray()
    val mac = hmac.compute(counterBytes)
    val offset = mac.last().and(0x0f).toInt()
    val truncatedMac = (mac[offset].toInt() and 0x7f shl 24
      or (mac[offset + 1].toInt() and 0xff shl 16)
      or (mac[offset + 2].toInt() and 0xff shl 8)
      or (mac[offset + 3].toInt() and 0xff))
    val code = truncatedMac.rem(10.toDouble().pow(codeLength.toDouble())).toInt()
    return code.toString().padStart(codeLength, '0')
  }

  suspend fun verify(code: String, counter: Long): Boolean =
    if (code.length != codeLength) false else code == generate(counter)

  abstract fun toUriString(): String

  protected fun StringBuilder.appendCommon(
    hmacType: Hmac.Type, hmacKey: ByteArray, otpType: String, issuer: String, accountName: String
  ) {
    append("otpauth://$otpType/")
    append("$issuer:$accountName")
    append("?secret=${hmacKey.encodeBase32ToString()}")
    append("&issuer=$issuer")
    append("&algorithm=${hmacType.name}")
    append("&digits=$codeLength")
  }

  companion object {
    @JvmStatic
    fun String.toOtp(): Otp? {
      val schema = substring(0, 10)
      if (schema != "otpauth://") {
        return null
      }
      val otpType = substring(10, 15)
      if ("hotp/" == otpType || "totp/" == otpType) {
        val segments = substring(15, length).split("?")
        if (segments.size < 2) {
          return null
        }
        val labels = segments[0].split(":")
        if (labels.size < 2) {
          return null
        }
        val issuer = labels[0]
        val accountName = labels[1]
        val parameters = mutableMapOf<String, String>()
        segments[1].split("&").forEach {
          val pair = it.split("=")
          if (pair.size > 1) {
            parameters[pair[0]] = pair[1]
          }
        }
        val base32Secret = parameters["secret"] ?: return null
        val secret = base32Secret.decodeBase32ToBytes() ?: return null
        val algorithmName = parameters["algorithm"] ?: ""
        val algorithm = Hmac.Type.values().find { it.name == algorithmName } ?: Hmac.Type.SHA1
        val digits = parameters["digits"]?.toIntOrNull() ?: 6
        return if ("hotp/" == otpType) {
          val counter = parameters["counter"]?.toLongOrNull() ?: 0
          Hotp(algorithm, secret, counter, digits, issuer, accountName)
        } else {
          val period = parameters["period"]?.toIntOrNull() ?: 30
          Totp(algorithm, secret, period, digits, issuer, accountName)
        }
      }
      return null
    }
  }
}
