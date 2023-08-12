package diglol.crypto

import diglol.crypto.internal.refToOrElse
import diglol.crypto.internal.selfOrCopyOf
import diglol.crypto.random.nextBytes
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.cValue
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.refTo
import kotlinx.cinterop.value
import platform.CoreCrypto.CCCrypt
import platform.CoreCrypto.CCOperation
import platform.CoreCrypto.kCCAlgorithmAES128
import platform.CoreCrypto.kCCBlockSizeAES128
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt
import platform.CoreCrypto.kCCOptionPKCS7Padding
import platform.CoreCrypto.kCCSuccess
import platform.posix.size_tVar

// https://datatracker.ietf.org/doc/html/rfc3602
actual class AesCbc actual constructor(
  internal actual val key: ByteArray,
  internal actual val iv: ByteArray?
) : Cipher {
  init {
    checkKey()
    checkIv()
  }

  actual override suspend fun encrypt(plaintext: ByteArray): ByteArray {
    checkPlaintext(plaintext)
    val realIv = iv ?: nextBytes(IV_SIZE)
    return realIv + doFinal(kCCEncrypt, key, realIv, plaintext)
  }

  actual override suspend fun decrypt(ciphertext: ByteArray): ByteArray {
    checkCiphertext(ciphertext)
    val iv = ciphertext.copyOf(IV_SIZE)
    val rawCiphertext = ciphertext.copyOfRange(IV_SIZE, ciphertext.size)
    return doFinal(kCCDecrypt, key, iv, rawCiphertext)
  }

  @OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
  private fun doFinal(
    op: CCOperation,
    key: ByteArray,
    iv: ByteArray,
    data: ByteArray
  ): ByteArray = memScoped {
    val outSize = data.size + (if (op == kCCEncrypt) kCCBlockSizeAES128.toInt() else 0)
    val out = ByteArray(outSize)
    val dataOutMoved = cValue<size_tVar>().ptr
    val status = CCCrypt(
      op,
      kCCAlgorithmAES128,
      kCCOptionPKCS7Padding,
      key.refTo(0),
      key.size.convert(),
      iv.refTo(0),
      data.refToOrElse(0),
      data.size.convert(),
      out.refTo(0),
      outSize.convert(),
      dataOutMoved
    )
    if (status == kCCSuccess) {
      val realOutSize = dataOutMoved.pointed.value.toInt()
      return out.selfOrCopyOf(realOutSize)
    } else {
      throw Error("Aes cbc ${if (op == kCCEncrypt) "encrypt" else "decrypt"} error: $status")
    }
  }

  actual companion object {
    actual val IV_SIZE: Int = AES_CBC_IV_SIZE
  }
}
