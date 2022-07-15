package diglol.crypto

import diglol.crypto.random.nextBytes
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.BenchmarkMode
import kotlinx.benchmark.BenchmarkTimeUnit
import kotlinx.benchmark.Measurement
import kotlinx.benchmark.Mode
import kotlinx.benchmark.OutputTimeUnit
import kotlinx.benchmark.Param
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.coroutines.test.runTest

@State(Scope.Benchmark)
@Measurement(iterations = 5, time = 1)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(BenchmarkTimeUnit.MICROSECONDS)
class Argon2Benchmark {
  @Param("1_64_1", "2_64_1", "2_64_2", "3_256_2")
  var factor = ""

  private val password = nextBytes(16)
  private val salt = nextBytes(32)

  private lateinit var i: Argon2
  private lateinit var d: Argon2
  private lateinit var id: Argon2

  @Setup
  fun setup() {
    val params = factor.split("_").map { it.toInt() }
    i = Argon2(Argon2.Version.V13, Argon2.Type.I, params[0], params[1], params[2], 32)
    d = Argon2(Argon2.Version.V13, Argon2.Type.D, params[0], params[1], params[2], 32)
    id = Argon2(Argon2.Version.V13, Argon2.Type.ID, params[0], params[1], params[2], 32)
  }

  @Benchmark
  fun i() = runTest {
    i.deriveKey(password, salt)
  }

  @Benchmark
  fun d() = runTest {
    d.deriveKey(password, salt)
  }

  @Benchmark
  fun id() = runTest {
    id.deriveKey(password, salt)
  }
}
