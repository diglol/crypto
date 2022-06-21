package diglol.crypto

import diglol.encoding.decodeHexToBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.test.runTest

class EncryptThenMacTest {
  @Suppress("ArrayInDataClass")
  private data class Sample(
    val encKey: ByteArray,
    val macKey: ByteArray,
    val plaintext: ByteArray,
    val iv: ByteArray,
    val aad: ByteArray,
    val ciphertext: ByteArray,
    val macAlg: Hmac.Type,
    val macSize: Int
  )

  // https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
  private val encryptThenMacSamples = listOf(
    Sample(
      "101112131415161718191a1b1c1d1e1f".decodeHexToBytes()!!,
      "000102030405060708090a0b0c0d0e0f".decodeHexToBytes()!!,
      ("41206369706865722073797374656d20"
        + "6d757374206e6f742062652072657175"
        + "6972656420746f206265207365637265"
        + "742c20616e64206974206d7573742062"
        + "652061626c6520746f2066616c6c2069"
        + "6e746f207468652068616e6473206f66"
        + "2074686520656e656d7920776974686f"
        + "757420696e636f6e76656e69656e6365").decodeHexToBytes()!!,
      "1af38c2dc2b96ffdd86694092341bc04".decodeHexToBytes()!!,
      ("546865207365636f6e64207072696e63"
        + "69706c65206f66204175677573746520"
        + "4b6572636b686f666673").decodeHexToBytes()!!,
      ("1af38c2dc2b96ffdd86694092341bc04"
        + "c80edfa32ddf39d5ef00c0b468834279"
        + "a2e46a1b8049f792f76bfe54b903a9c9"
        + "a94ac9b47ad2655c5f10f9aef71427e2"
        + "fc6f9b3f399a221489f16362c7032336"
        + "09d45ac69864e3321cf82935ac4096c8"
        + "6e133314c54019e8ca7980dfa4b9cf1b"
        + "384c486f3a54c51078158ee5d79de59f"
        + "bd34d848b3d69550a67646344427ade5"
        + "4b8851ffb598f7f80074b9473c82e2db"
        + "652c3fa36b0a7c5b3219fab3a30bc1c4").decodeHexToBytes()!!,
      Hmac.Type.SHA256,
      16
    ),
    Sample(
      "18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637".decodeHexToBytes()!!,
      "000102030405060708090a0b0c0d0e0f1011121314151617".decodeHexToBytes()!!,
      ("41206369706865722073797374656d20"
        + "6d757374206e6f742062652072657175"
        + "6972656420746f206265207365637265"
        + "742c20616e64206974206d7573742062"
        + "652061626c6520746f2066616c6c2069"
        + "6e746f207468652068616e6473206f66"
        + "2074686520656e656d7920776974686f"
        + "757420696e636f6e76656e69656e6365").decodeHexToBytes()!!,
      "1af38c2dc2b96ffdd86694092341bc04".decodeHexToBytes()!!,
      ("546865207365636f6e64207072696e63"
        + "69706c65206f66204175677573746520"
        + "4b6572636b686f666673").decodeHexToBytes()!!,
      ("1af38c2dc2b96ffdd86694092341bc04"
        + "893129b0f4ee9eb18d75eda6f2aaa9f3"
        + "607c98c4ba0444d34162170d8961884e"
        + "58f27d4a35a5e3e3234aa99404f327f5"
        + "c2d78e986e5749858b88bcddc2ba0521"
        + "8f195112d6ad48fa3b1e89aa7f20d596"
        + "682f10b3648d3bb0c983c3185f59e36d"
        + "28f647c1c13988de8ea0d821198c1509"
        + "77e28ca768080bc78c35faed69d8c0b7"
        + "d9f506232198a489a1a6ae03a319fb30"
        + "dd131d05ab3467dd056f8e882bad7063"
        + "7f1e9a541d9c23e7").decodeHexToBytes()!!,
      Hmac.Type.SHA384,
      24
    ),
    Sample(
      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".decodeHexToBytes()!!,
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".decodeHexToBytes()!!,
      ("41206369706865722073797374656d20"
        + "6d757374206e6f742062652072657175"
        + "6972656420746f206265207365637265"
        + "742c20616e64206974206d7573742062"
        + "652061626c6520746f2066616c6c2069"
        + "6e746f207468652068616e6473206f66"
        + "2074686520656e656d7920776974686f"
        + "757420696e636f6e76656e69656e6365").decodeHexToBytes()!!,
      "1af38c2dc2b96ffdd86694092341bc04".decodeHexToBytes()!!,
      ("546865207365636f6e64207072696e63"
        + "69706c65206f66204175677573746520"
        + "4b6572636b686f666673").decodeHexToBytes()!!,
      ("1af38c2dc2b96ffdd86694092341bc04"
        + "4affaaadb78c31c5da4b1b590d10ffbd"
        + "3dd8d5d302423526912da037ecbcc7bd"
        + "822c301dd67c373bccb584ad3e9279c2"
        + "e6d12a1374b77f077553df829410446b"
        + "36ebd97066296ae6427ea75c2e0846a1"
        + "1a09ccf5370dc80bfecbad28c73f09b3"
        + "a3b75e662a2594410ae496b2e2e6609e"
        + "31e6e02cc837f053d21f37ff4f51950b"
        + "be2638d09dd7a4930930806d0703b1f6"
        + "4dd3b4c088a7f45c216839645b2012bf"
        + "2e6269a8c56a816dbc1b267761955bc5").decodeHexToBytes()!!,
      Hmac.Type.SHA512,
      32
    ),
  )

  @Test
  fun encrypt() = runTest {
    encryptThenMacSamples.forEachIndexed { index, (encKey, macKey, plaintext, iv, aad, ciphertext, macAlg, macSize) ->
      val aesCbc = AesCbc(encKey, iv)
      val hmac = Hmac(macAlg, macKey)
      val encryptThenMac = EncryptThenMac(aesCbc, hmac, macSize)
      val actual = encryptThenMac.encrypt(plaintext, aad)
      assertContentEquals(ciphertext, actual, index.toString())
    }
  }

  @Test
  fun decrypt() = runTest {
    encryptThenMacSamples.forEachIndexed { index, (encKey, macKey, plaintext, iv, aad, ciphertext, macAlg, macSize) ->
      val aesCbc = AesCbc(encKey, iv)
      val hmac = Hmac(macAlg, macKey)
      val encryptThenMac = EncryptThenMac(aesCbc, hmac, macSize)
      val actual = encryptThenMac.decrypt(ciphertext, aad)
      assertContentEquals(plaintext, actual, index.toString())
    }
  }
}
