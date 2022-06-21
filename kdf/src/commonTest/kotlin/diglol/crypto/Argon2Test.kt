package diglol.crypto

import diglol.encoding.decodeHexToBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlinx.coroutines.test.runTest

// https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
class Argon2Test {
  private data class Sample(
    val iterations: Int,
    val memory: Int,
    val parallelism: Int,
    val result: String
  )

  private val iSamples = listOf(
    Sample(1, 64, 1, "b9c401d1844a67d50eae3967dc28870b22e508092e861a37"),
    Sample(2, 64, 1, "8cf3d8f76a6617afe35fac48eb0b7433a9a670ca4a07ed64"),
    Sample(2, 64, 2, "2089f3e78a799720f80af806553128f29b132cafe40d059f"),
    Sample(3, 256, 2, "f5bbf5d4c3836af13193053155b73ec7476a6a2eb93fd5e6"),
  )

  private val dSamples = listOf(
    Sample(1, 64, 1, "8727405fd07c32c78d64f547f24150d3f2e703a89f981a19"),
    Sample(2, 64, 1, "3be9ec79a69b75d3752acb59a1fbb8b295a46529c48fbb75"),
    Sample(2, 64, 2, "68e2462c98b8bc6bb60ec68db418ae2c9ed24fc6748a40e9"),
    Sample(3, 256, 2, "f4f0669218eaf3641f39cc97efb915721102f4b128211ef2"),
  )

  private val idSamples = listOf(
    Sample(1, 64, 1, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"),
    Sample(2, 64, 1, "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"),
    Sample(2, 64, 2, "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"),
    Sample(3, 256, 2, "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b"),
  )

  @Test
  fun i() = runTest {
    try {
      iSamples.forEachIndexed { index, (iterations, memory, parallelism, result) ->
        val expect = result.decodeHexToBytes()!!
        val argon2 =
          Argon2(Argon2.Version.V13, Argon2.Type.I, iterations, memory, parallelism, expect.size)
        val hash = argon2.deriveKey("password".encodeToByteArray(), "somesalt".encodeToByteArray())
        assertContentEquals(expect, hash, index.toString())
      }
    } catch (e: kotlin.Error) {
      if (e.message?.contains("argon2") != true) { // ignore argon2 error on Android
        throw e
      }
    }
  }

  @Test
  fun d() = runTest {
    try {
      dSamples.forEachIndexed { index, (iterations, memory, parallelism, result) ->
        val expect = result.decodeHexToBytes()!!
        val argon2 =
          Argon2(Argon2.Version.V13, Argon2.Type.D, iterations, memory, parallelism, expect.size)
        val hash = argon2.deriveKey("password".encodeToByteArray(), "somesalt".encodeToByteArray())
        assertContentEquals(expect, hash, index.toString())
      }
    } catch (e: kotlin.Error) {
      if (e.message?.contains("argon2") != true) {
        throw e
      }
    }
  }

  @Test
  fun id() = runTest {
    try {
      idSamples.forEachIndexed { index, (iterations, memory, parallelism, result) ->
        val expect = result.decodeHexToBytes()!!
        val argon2 =
          Argon2(Argon2.Version.V13, Argon2.Type.ID, iterations, memory, parallelism, expect.size)
        val hash = argon2.deriveKey("password".encodeToByteArray(), "somesalt".encodeToByteArray())
        assertContentEquals(expect, hash, index.toString())
      }
    } catch (e: kotlin.Error) {
      if (e.message?.contains("argon2") != true) {
        throw e
      }
    }
  }
}
