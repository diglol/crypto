package diglol.crypto

import diglol.encoding.decodeHexToBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest

@OptIn(ExperimentalCoroutinesApi::class)
class Poly1305Test {
  // https://tools.ietf.org/html/rfc7539#appendix-A.3
  private val poly1305Samples = listOf(
    Triple(
      "0000000000000000000000000000000000000000000000000000000000000000".decodeHexToBytes(),
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".decodeHexToBytes(),
      "00000000000000000000000000000000".decodeHexToBytes()
    ),
    Triple(
      "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e".decodeHexToBytes(),
      ("Any submission to the IETF intended by the Contributor for publication as all or "
        + "part of an IETF Internet-Draft or RFC and any statement made within the context "
        + "of an IETF activity is considered an \"IETF Contribution\". Such statements "
        + "include oral statements in IETF sessions, as well as written and electronic "
        + "communications made at any time or place, which are addressed to").encodeToByteArray(),
      "36e5f6b5c5e06070f0efca96227a863e".decodeHexToBytes()
    ),
    Triple(
      "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000".decodeHexToBytes(),
      ("Any submission to the IETF intended by the Contributor for publication as all or "
        + "part of an IETF Internet-Draft or RFC and any statement made within the context "
        + "of an IETF activity is considered an \"IETF Contribution\". Such statements "
        + "include oral statements in IETF sessions, as well as written and electronic "
        + "communications made at any time or place, which are addressed to").encodeToByteArray(),
      "f3477e7cd95417af89a6b8794c310cf0".decodeHexToBytes()
    ),
    Triple(
      "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0".decodeHexToBytes(),
      ("2754776173206272696c6c69672c2061"
        + "6e642074686520736c6974687920746f"
        + "7665730a446964206779726520616e64"
        + "2067696d626c6520696e207468652077"
        + "6162653a0a416c6c206d696d73792077"
        + "6572652074686520626f726f676f7665"
        + "732c0a416e6420746865206d6f6d6520"
        + "7261746873206f757467726162652e").decodeHexToBytes(),
      "4541669a7eaaee61e708dc7cbcc5eb62".decodeHexToBytes()
    ),
    Triple(
      "0200000000000000000000000000000000000000000000000000000000000000".decodeHexToBytes(),
      "ffffffffffffffffffffffffffffffff".decodeHexToBytes(),
      "03000000000000000000000000000000".decodeHexToBytes()
    ),
    Triple(
      "02000000000000000000000000000000ffffffffffffffffffffffffffffffff".decodeHexToBytes(),
      "02000000000000000000000000000000".decodeHexToBytes(),
      "03000000000000000000000000000000".decodeHexToBytes()
    ),
    Triple(
      "0100000000000000000000000000000000000000000000000000000000000000".decodeHexToBytes(),
      ("ffffffffffffffffffffffffffffffff"
        + "f0ffffffffffffffffffffffffffffff"
        + "11000000000000000000000000000000").decodeHexToBytes(),
      "05000000000000000000000000000000".decodeHexToBytes()
    ),
    Triple(
      "0100000000000000000000000000000000000000000000000000000000000000".decodeHexToBytes(),
      ("ffffffffffffffffffffffffffffffff"
        + "fbfefefefefefefefefefefefefefefe"
        + "01010101010101010101010101010101").decodeHexToBytes(),
      "00000000000000000000000000000000".decodeHexToBytes()
    )
  )

  @Test
  fun poly1305() = runTest {
    poly1305Samples.forEachIndexed { index, (key, data, expect) ->
      val poly1305 = Poly1305(key!!)
      val actual = poly1305.compute(data!!)
      assertContentEquals(expect, actual)
      assertTrue(poly1305.verify(expect!!, data), index.toString())
    }
  }
}
