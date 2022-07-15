package diglol.crypto

import kotlin.random.Random
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
class Pbkdf2Benmark {
  @Param("1", "512", "1024", "4096")
  var factor = 0
  private lateinit var data: ByteArray

  @Setup
  fun setup() {
    data = Random.nextBytes(factor)
  }

  @Benchmark
  fun sha1() = runTest {
    val hash = Hash(Hash.Type.SHA1)
    hash.hash(data)
  }

  @Benchmark
  fun sha256() = runTest {
    val hash = Hash(Hash.Type.SHA256)
    hash.hash(data)
  }

  @Benchmark
  fun sha384() = runTest {
    val hash = Hash(Hash.Type.SHA384)
    hash.hash(data)
  }

  @Benchmark
  fun sha512() = runTest {
    val hash = Hash(Hash.Type.SHA512)
    hash.hash(data)
  }
}
