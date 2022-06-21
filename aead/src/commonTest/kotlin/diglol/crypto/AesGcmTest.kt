package diglol.crypto

import diglol.crypto.internal.emptyBytes
import diglol.encoding.decodeHexToBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.test.runTest

class AesGcmTest {
  @Suppress("ArrayInDataClass")
  private data class Sample(
    val key: ByteArray,
    val none: ByteArray,
    val plaintext: ByteArray,
    val ad: ByteArray,
    val ciphertext: ByteArray
  )

  // https://cs.opensource.google/go/go/+/refs/tags/go1.18.3:src/crypto/cipher/gcm_test.go
  private val aesGcmSamples = listOf(
    Sample(
      "11754cd72aec309bf52f7687212e8957".decodeHexToBytes()!!,
      "3c819d9a9bed087615030b65".decodeHexToBytes()!!,
      emptyBytes,
      emptyBytes,
      "250327c674aaf477aef2675748cf6971".decodeHexToBytes()!!
    ),
    Sample(
      "fbe3467cc254f81be8e78d765a2e6333".decodeHexToBytes()!!,
      "c6697351ff4aec29cdbaabf2".decodeHexToBytes()!!,
      emptyBytes,
      "67".decodeHexToBytes()!!,
      "3659cdc25288bf499ac736c03bfc1159".decodeHexToBytes()!!
    ),
    Sample(
      "051758e95ed4abb2cdc69bb454110e82".decodeHexToBytes()!!,
      "c99a66320db73158a35a255d".decodeHexToBytes()!!,
      emptyBytes,
      "67c6697351ff4aec29cdbaabf2fbe3467cc254f81be8e78d765a2e63339f".decodeHexToBytes()!!,
      "6ce77f1a5616c505b6aec09420234036".decodeHexToBytes()!!
    ),
    Sample(
      "ab72c77b97cb5fe9a382d9fe81ffdbed".decodeHexToBytes()!!,
      "54cc7dc2c37ec006bcc6d1da".decodeHexToBytes()!!,
      "007c5e5b3e59df24a7c355584fc1518d".decodeHexToBytes()!!,
      emptyBytes,
      "0e1bde206a07a9c2c1b65300f8c649972b4401346697138c7a4891ee59867d0c".decodeHexToBytes()!!
    ),
    Sample(
      "fe47fcce5fc32665d2ae399e4eec72ba".decodeHexToBytes()!!,
      "5adb9609dbaeb58cbd6e7275".decodeHexToBytes()!!,
      "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429bea063".decodeHexToBytes()!!,
      "88319d6e1d3ffa5f987199166c8a9b56c2aeba5a".decodeHexToBytes()!!,
      "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269e5db3e291ef1982e4defedaa2249f898556b47".decodeHexToBytes()!!
    ),
    Sample(
      "d9f7d2411091f947b4d6f1e2d1f0fb2e".decodeHexToBytes()!!,
      "e1934f5db57cc983e6b180e7".decodeHexToBytes()!!,
      "73ed042327f70fe9c572a61545eda8b2a0c6e1d6c291ef19248e973aee6c312012f490c2c6f6166f4a59431e182663fcaea05a".decodeHexToBytes()!!,
      "0a8a18a7150e940c3d87b38e73baee9a5c049ee21795663e264b694a949822b639092d0e67015e86363583fcf0ca645af9f43375f05fdb4ce84f411dcbca73c2220dea03a20115d2e51398344b16bee1ed7c499b353d6c597af8".decodeHexToBytes()!!,
      "aaadbd5c92e9151ce3db7210b8714126b73e43436d242677afa50384f2149b831f1d573c7891c2a91fbc48db29967ec9542b2321b51ca862cb637cdd03b99a0f93b134".decodeHexToBytes()!!
    )
  )

  @Test
  fun encrypt() = runTest {
    aesGcmSamples.forEachIndexed { index, (key, none, plaintext, ad, ciphertext) ->
      val aesGcm = AesGcm(key, none)
      val actual = aesGcm.encrypt(plaintext, ad)
      assertContentEquals(none + ciphertext, actual, index.toString())
    }
  }

  @Test
  fun decrypt() = runTest {
    aesGcmSamples.forEachIndexed { index, (key, none, plaintext, ad, ciphertext) ->
      val aesGcm = AesGcm(key, none)
      val actual = aesGcm.decrypt(none + ciphertext, ad)
      assertContentEquals(plaintext, actual, index.toString())
    }
  }
}
