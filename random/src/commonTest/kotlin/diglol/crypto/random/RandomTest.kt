package diglol.crypto.random

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

class RandomTest {
  @Test
  fun nextInt() {
    assertFailsWith<IllegalArgumentException> { nextInt(0) }
    assertFailsWith<IllegalArgumentException> { nextInt(-1) }
    assertFailsWith<IllegalArgumentException> { nextInt(Int.MIN_VALUE) }

    repeat(100) {
      assertEquals(0, nextInt(1))
    }

    for (bound in arrayOf(1, 9, 29, 0x900_0000, Int.MAX_VALUE)) {
      repeat(100) {
        val x = nextInt(bound)
        if (x !in 0 until bound)
          fail("Value $x must be in range [0, $bound)")
      }
    }
  }

  @Test
  fun nextBytes() {
    val size = 100
    val bytes1 = nextBytes(size)
    assertEquals(bytes1.size, size)

    val result = mutableSetOf<ByteArray>()
    repeat(100) {
      assertTrue(result.add(nextBytes(10)))
    }

    assertTrue(nextBytes(65535).size == 65535)
    assertTrue(nextBytes(65536).size == 65536)
    assertTrue(nextBytes(65537).size == 65537)
    assertTrue(nextBytes(100000).size == 100000)
  }
}
