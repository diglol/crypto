package diglol.crypto

import diglol.crypto.internal.emptyBytes
import diglol.encoding.decodeHexToBytes
import diglol.encoding.encodeHexToString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest

@OptIn(ExperimentalCoroutinesApi::class)
class HashTest {
  private val sha1 = Hash(Hash.Type.SHA1)
  private val sha256 = Hash(Hash.Type.SHA256)
  private val sha384 = Hash(Hash.Type.SHA384)
  private val sha512 = Hash(Hash.Type.SHA512)

  //https://datatracker.ietf.org/doc/html/rfc4634#section-8.4
  private val sha1Samples = listOf(
    Triple(emptyBytes, 1, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"),
    Triple("abc".encodeToByteArray(), 1, "A9993E364706816ABA3E25717850C26C9CD0D89D"),
    Triple(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".encodeToByteArray(),
      1,
      "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
    ),
    Triple("a".encodeToByteArray(), 1000000, "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"),
    Triple(
      "0123456701234567012345670123456701234567012345670123456701234567".encodeToByteArray(),
      10,
      "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452"
    ),
    Triple("5E".decodeHexToBytes()!!, 1, "5E6F80A34A9798CAFC6A5DB96CC57BA4C4DB59C2")

  )

  // https://datatracker.ietf.org/doc/html/rfc4634#section-8.4
  private val sha256Samples = listOf(
    Triple(emptyBytes, 1, "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
    Triple(
      "abc".encodeToByteArray(),
      1,
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    ),
    Triple(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".encodeToByteArray(),
      1,
      "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
    ),
    Triple(
      "a".encodeToByteArray(),
      1000000,
      "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"
    ),
    Triple(
      "0123456701234567012345670123456701234567012345670123456701234567".encodeToByteArray(),
      10,
      "594847328451BDFA85056225462CC1D867D877FB388DF0CE35F25AB5562BFBB5"
    ),
    Triple(
      "19".decodeHexToBytes()!!,
      1,
      "68AA2E2EE5DFF96E3355E6C7EE373E3D6A4E17F75F9518D843709C0C9BC3E3D4"
    )
  )

  // https://datatracker.ietf.org/doc/html/rfc4634#section-8.4
  private val sha384Samples = listOf(
    Triple(
      emptyBytes,
      1,
      "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
    ),
    Triple(
      "abc".encodeToByteArray(),
      1,
      "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"
    ),
    Triple(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".encodeToByteArray(),
      1,
      "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039"
    ),
    Triple(
      "a".encodeToByteArray(),
      1000000,
      "9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B07B8B3DC38ECC4EBAE97DDD87F3D8985"
    ),
    Triple(
      "0123456701234567012345670123456701234567012345670123456701234567".encodeToByteArray(),
      10,
      "2FC64A4F500DDB6828F6A3430B8DD72A368EB7F3A8322A70BC84275B9C0B3AB00D27A5CC3C2D224AA6B61A0D79FB4596"
    ),
    Triple(
      "B9".decodeHexToBytes()!!,
      1,
      "BC8089A19007C0B14195F4ECC74094FEC64F01F90929282C2FB392881578208AD466828B1C6C283D2722CF0AD1AB6938"
    )
  )

  // https://datatracker.ietf.org/doc/html/rfc4634#section-8.4
  private val sha512Samples = listOf(
    Triple(
      emptyBytes,
      1,
      "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
    ),
    Triple(
      "abc".encodeToByteArray(),
      1,
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
    ),
    Triple(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".encodeToByteArray(),
      1,
      "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909"
    ),
    Triple(
      "a".encodeToByteArray(),
      1000000,
      "E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B"
    ),
    Triple(
      "0123456701234567012345670123456701234567012345670123456701234567".encodeToByteArray(),
      10,
      "89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024DB872D1ABD2BA8141A0F85072A9BE1E2AA04CF33C765CB510813A39CD5A84C4ACAA64D3F3FB7BAE9"
    ),
    Triple(
      "D0".decodeHexToBytes()!!,
      1,
      "9992202938E882E73E20F6B69E68A0A7149090423D93C81BAB3F21678D4ACEEEE50E4E8CAFADA4C85A54EA8306826C4AD6E74CECE9631BFA8A549B4AB3FBBA15"
    )
  )

  private fun repeatValue(value: ByteArray, times: Int): ByteArray {
    val result = ByteArray(times * value.size)
    repeat(times) {
      value.copyInto(result, value.size * it, 0, value.size)
    }
    return result
  }

  @Test
  fun sha1() = runTest {
    sha1Samples.forEachIndexed { index, (value, times, expect) ->
      assertEquals(
        expect,
        sha1.hash(repeatValue(value, times)).encodeHexToString(),
        index.toString()
      )
    }
  }

  @Test
  fun sha256() = runTest {
    sha256Samples.forEachIndexed { index, (value, times, expect) ->
      assertEquals(
        expect,
        sha256.hash(repeatValue(value, times)).encodeHexToString(),
        index.toString()
      )
    }
  }

  @Test
  fun sha384() = runTest {
    sha384Samples.forEachIndexed { index, (value, times, expect) ->
      assertEquals(
        expect,
        sha384.hash(repeatValue(value, times)).encodeHexToString(),
        index.toString()
      )
    }
  }

  @Test
  fun sha512() = runTest {
    sha512Samples.forEachIndexed { index, (value, times, expect) ->
      assertEquals(
        expect,
        sha512.hash(repeatValue(value, times)).encodeHexToString(),
        index.toString()
      )
    }
  }
}
