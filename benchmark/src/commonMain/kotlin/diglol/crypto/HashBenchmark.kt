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
class HashBenchmark {
  @Param("1024", "10240", "102400")
  var factor = 0
  private lateinit var data: ByteArray

  private val sha1 = Hash(Hash.Type.SHA1)
  private val sha256 = Hash(Hash.Type.SHA256)
  private val sha384 = Hash(Hash.Type.SHA384)
  private val sha512 = Hash(Hash.Type.SHA512)

  @Setup
  fun setup() {
    data = Random.nextBytes(factor)
  }

  @Benchmark
  fun sha1() = runTest {
    sha1.hash(data)
  }

  @Benchmark
  fun sha256() = runTest {
    sha256.hash(data)
  }

  @Benchmark
  fun sha384() = runTest {
    sha384.hash(data)
  }

  @Benchmark
  fun sha512() = runTest {
    sha512.hash(data)
  }
}
