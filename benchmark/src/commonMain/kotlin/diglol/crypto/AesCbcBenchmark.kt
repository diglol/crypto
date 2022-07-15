package diglol.crypto

import diglol.crypto.random.nextBytes
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
class AesCbcBenchmark {
  @Param("1024", "10240", "102400")
  var factor = 0
  private lateinit var data: ByteArray

  private val aesCbc128 = AesCbc(nextBytes(16))
  private lateinit var result128: ByteArray
  private val aesCbc256 = AesCbc(nextBytes(32))
  private lateinit var result256: ByteArray

  @Setup
  fun setup() = runTest {
    data = Random.nextBytes(factor)
    result128 = aesCbc128.encrypt(data)
    result256 = aesCbc256.encrypt(data)
  }

  @Benchmark
  fun encrypt128() = runTest {
    aesCbc128.encrypt(data)
  }

  @Benchmark
  fun decrypt128() = runTest {
    aesCbc128.decrypt(result128)
  }

  @Benchmark
  fun encrypt256() = runTest {
    aesCbc256.encrypt(data)
  }

  @Benchmark
  fun decrypt256() = runTest {
    aesCbc256.decrypt(result256)
  }
}
