package diglol.crypto

import diglol.crypto.internal.emptyBytes
import diglol.encoding.decodeHexToBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.test.runTest

class XChaCha20Poly1305Test {
  @Suppress("ArrayInDataClass")
  private data class Sample(
    val key: ByteArray,
    val none: ByteArray,
    val aad: ByteArray,
    val plaintext: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray
  )

  // https://github.com/google/wycheproof/blob/master/testvectors/xchacha20_poly1305_test.json
  private val xChaCha20Poly1305Samples = listOf(
    Sample(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f".decodeHexToBytes()!!,
      "404142434445464748494a4b4c4d4e4f5051525354555657".decodeHexToBytes()!!,
      "50515253c0c1c2c3c4c5c6c7".decodeHexToBytes()!!,
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e".decodeHexToBytes()!!,
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e".decodeHexToBytes()!!,
      "c0875924c1c7987947deafd8780acf49".decodeHexToBytes()!!,
    ),
    Sample(
      "ab1562faea9f47af3ae1c3d6d030e3af230255dff3df583ced6fbbcbf9d606a9".decodeHexToBytes()!!,
      "6a5e0c4617e07091b605a4de2c02dde117de2ebd53b23497".decodeHexToBytes()!!,
      emptyBytes,
      emptyBytes,
      emptyBytes,
      "e2697ea6877aba39d9555a00e14db041".decodeHexToBytes()!!,
    ),
    Sample(
      "303ccb2e1567c3d9f629a5c632dbc62a9a82c525674f67988b31bd1dee990538".decodeHexToBytes()!!,
      "05188738844ab90a8b11beef38eaec3e100d8f4f85ae7a41".decodeHexToBytes()!!,
      emptyBytes,
      "62".decodeHexToBytes()!!,
      "45".decodeHexToBytes()!!,
      "d15734f984d749fa3f0550a70c43dddf".decodeHexToBytes()!!,
    ),
    Sample(
      "697c197c9e0023c8eee42ddf08c12c46718a436561b0c66d998c81879f7cb74c".decodeHexToBytes()!!,
      "cd78f4533c94648feacd5aef0291b00b454ee3dcdb76dcc8".decodeHexToBytes()!!,
      "6384f4714ff18c18".decodeHexToBytes()!!,
      "e1".decodeHexToBytes()!!,
      "b0".decodeHexToBytes()!!,
      "e5e35f5332f91bdd2d28e59d68a0b141".decodeHexToBytes()!!,
    ),
    Sample(
      "c11213bcff39a88b0e3ecc47b23acf6c3014e4708d80dcca162da7377b316ab3".decodeHexToBytes()!!,
      "b60ca1ab736deebe4d9da78bc7cbbab91be14a2f884240b7".decodeHexToBytes()!!,
      emptyBytes,
      "57f9".decodeHexToBytes()!!,
      "5e03".decodeHexToBytes()!!,
      "eed21c2cd3f395538d677602964ed578".decodeHexToBytes()!!,
    ),
    Sample(
      "b720aea3df85fb3fb00583eddbebc5c545bcdcb7f6f2a94c1087950e16d68278".decodeHexToBytes()!!,
      "1436f36466fce5db337a73ec18e269e6e985d91035128183".decodeHexToBytes()!!,
      "9d53316bd2aa3e3d".decodeHexToBytes()!!,
      "4799c4".decodeHexToBytes()!!,
      "d41c02".decodeHexToBytes()!!,
      "8faa889d7f189cd9473e19200ef03920".decodeHexToBytes()!!,
    ),
    Sample(
      "7fb18b56f3f5122585754a3b6c6a4e523036e66793db569c3e8e28032e916eb6".decodeHexToBytes()!!,
      "c02c8c595064ac303b1be5df6ab43048856e97ae9962fb8f".decodeHexToBytes()!!,
      "8981c7260d514ab6".decodeHexToBytes()!!,
      "6e8c0bb3361908f5b33e059408651ae3".decodeHexToBytes()!!,
      "a7eb11bfaa0d1c2ce457598049399575".decodeHexToBytes()!!,
      "485a94f61aa5f47a3036e85a57effd2f".decodeHexToBytes()!!,
    ),
  )

  @Test
  fun encrypt() = runTest {
    xChaCha20Poly1305Samples.forEachIndexed { index, (key, none, aad, plaintext, ciphertext, tag) ->
      val xChaCha20Poly1305 = XChaCha20Poly1305(key, none)
      val actual = xChaCha20Poly1305.encrypt(plaintext, aad)
      assertContentEquals(none + ciphertext + tag, actual, index.toString())
    }
  }

  @Test
  fun decrypt() = runTest {
    xChaCha20Poly1305Samples.forEachIndexed { index, (key, none, aad, plaintext, ciphertext, tag) ->
      val xChaCha20Poly1305 = XChaCha20Poly1305(key)
      val actual = xChaCha20Poly1305.decrypt(none + ciphertext + tag, aad)
      assertContentEquals(plaintext, actual, index.toString())
    }
  }
}
