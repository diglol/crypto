package diglol.crypto

import diglol.encoding.decodeHexToBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.test.runTest

class XChaCha20Test {
  @Suppress("ArrayInDataClass")
  private data class Sample(
    val key: ByteArray,
    val none: ByteArray,
    val plaintext: ByteArray,
    val ciphertext: ByteArray
  )

  private val xChaChaSamples = listOf(
    // From libsodium's test/default/xchacha20.c
    Sample(
      "79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4".decodeHexToBytes()!!,
      "b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419".decodeHexToBytes()!!,
      "c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c".decodeHexToBytes()!!,
      ByteArray("c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c".decodeHexToBytes()!!.size),
    ),
    Sample(
      "ddf7784fee099612c40700862189d0397fcc4cc4b3cc02b5456b3a97d1186173".decodeHexToBytes()!!,
      "a9a04491e7bf00c3ca91ac7c2d38a777d88993a7047dfcc4".decodeHexToBytes()!!,
      "2f289d371f6f0abc3cb60d11d9b7b29adf6bc5ad843e8493e928448d".decodeHexToBytes()!!,
      ByteArray("2f289d371f6f0abc3cb60d11d9b7b29adf6bc5ad843e8493e928448d".decodeHexToBytes()!!.size)
    ),
    Sample(
      "3d12800e7b014e88d68a73f0a95b04b435719936feba60473f02a9e61ae60682".decodeHexToBytes()!!,
      "56bed2599eac99fb27ebf4ffcb770a64772dec4d5849ea2d".decodeHexToBytes()!!,
      "a2c3c1406f33c054a92760a8e0666b84f84fa3a618f0".decodeHexToBytes()!!,
      ByteArray("a2c3c1406f33c054a92760a8e0666b84f84fa3a618f0".decodeHexToBytes()!!.size)
    ),
    Sample(
      "5f5763ff9a30c95da5c9f2a8dfd7cc6efd9dfb431812c075aa3e4f32e04f53e4".decodeHexToBytes()!!,
      "a5fa890efa3b9a034d377926ce0e08ee6d7faccaee41b771".decodeHexToBytes()!!,
      "8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a52b0b6a0f51891528f424c4a7f492a8dd7bce8bac19fbdbe1fb379ac0".decodeHexToBytes()!!,
      ByteArray("8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a52b0b6a0f51891528f424c4a7f492a8dd7bce8bac19fbdbe1fb379ac0".decodeHexToBytes()!!.size)
    ),
    // https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-01#appendix-A.2
    Sample(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f".decodeHexToBytes()!!,
      "404142434445464748494a4b4c4d4e4f5051525354555658".decodeHexToBytes()!!,
      ("4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26"
        + "d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a15"
        + "8a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec"
        + "4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431ae"
        + "e769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8"
        + "d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d886"
        + "0920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790"
        + "a66393b93111c1a55dd7421a10184974c7c5").decodeHexToBytes()!!,
      ("5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2"
        + "061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e64207768"
        + "6973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f66206120476"
        + "5726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e67"
        + "2d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696"
        + "c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f"
        + "796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6"
        + "9632066616d696c792043616e696461652e").decodeHexToBytes()!!,
    ),
  )

  @Test
  fun encrypt() = runTest {
    xChaChaSamples.forEachIndexed { index, (key, none, ciphertext, plaintext) ->
      val xChaCha20 = XChaCha20(key, none, 0)
      val actual = xChaCha20.encrypt(plaintext)
      assertContentEquals(none + ciphertext, actual, index.toString())
    }
  }

  @Test
  fun decrypt() = runTest {
    xChaChaSamples.forEachIndexed { index, (key, none, ciphertext, plaintext) ->
      val xChaCha20 = XChaCha20(key, none, 0)
      val actual = xChaCha20.decrypt(none + ciphertext)
      assertContentEquals(plaintext, actual, index.toString())
    }
  }
}
