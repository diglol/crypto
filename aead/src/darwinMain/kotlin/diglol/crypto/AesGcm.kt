package diglol.crypto

import diglol.crypto.internal.IAGAesGcm
import diglol.crypto.internal.IAGCipheredData
import diglol.crypto.internal.plusByteArrays
import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toNSData
import diglol.crypto.random.nextBytes
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.Foundation.NSError

// https://datatracker.ietf.org/doc/html/rfc5288
actual class AesGcm actual constructor(
  internal actual val key: ByteArray,
  internal actual val iv: ByteArray?
) : Aead {
  init {
    checkKey()
    checkIv()
  }

  @Suppress("OPT_IN_USAGE")
  actual override suspend fun encrypt(
    plaintext: ByteArray,
    associatedData: ByteArray
  ): ByteArray = memScoped {
    checkPlaintext(plaintext)
    val errorPtr = alloc<ObjCObjectVar<NSError?>>().ptr
    val realIv = iv ?: nextBytes(IV_SIZE)
    val result = IAGAesGcm.cipheredDataByAuthenticatedEncryptingPlainData(
      plaintext.toNSData(),
      associatedData.toNSData(),
      TAG_SIZE.convert(),
      realIv.toNSData(),
      key.toNSData(),
      errorPtr
    )!!
    val nsError = errorPtr.pointed.value
    if (nsError == null) {
      val rawCiphertext = result.cipheredBuffer.toByteArray(result.cipheredBufferLength.convert())
      val tag = result.authenticationTag.toByteArray(result.authenticationTagLength.convert())
      return realIv.plusByteArrays(rawCiphertext, tag)
    } else {
      throw Error("Aes gcm encrypt error: ${nsError.code}")
    }
  }

  @Suppress("OPT_IN_USAGE")
  actual override suspend fun decrypt(
    ciphertext: ByteArray,
    associatedData: ByteArray
  ): ByteArray = memScoped {
    checkCiphertext(ciphertext)
    val iv = ciphertext.copyOf(IV_SIZE)
    val rawCiphertext = ciphertext.copyOfRange(IV_SIZE, ciphertext.size - TAG_SIZE)
    val tag = ciphertext.copyOfRange(ciphertext.size - TAG_SIZE, ciphertext.size)
    val errorPtr = alloc<ObjCObjectVar<NSError?>>().ptr
    val cipheredData = IAGCipheredData(
      if (rawCiphertext.isNotEmpty()) rawCiphertext.usePinned { it.addressOf(0) } else null,
      rawCiphertext.size.convert(),
      tag.usePinned { it.addressOf(0) },
      tag.size.convert()
    )
    val plaintext = IAGAesGcm.plainDataByAuthenticatedDecryptingCipheredData(
      cipheredData,
      associatedData.toNSData(),
      iv.toNSData(),
      key.toNSData(),
      errorPtr
    )
    val nsError = errorPtr.pointed.value
    if (nsError == null) {
      return plaintext!!.toByteArray()
    } else {
      throw Error("Aes gcm decrypt error: ${nsError.code}")
    }
  }

  actual companion object {
    actual val IV_SIZE: Int = AES_GCM_IV_SIZE
    actual val TAG_SIZE: Int = AES_GCM_TAG_SIZE
  }
}
