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
class AesGcmBenchmark {
  @Param("1024", "10240", "102400")
  var factor = 0
  private lateinit var data: ByteArray

  private val aesGcm128 = AesGcm(nextBytes(16))
  private lateinit var result128: ByteArray
  private val aesGcm256 = AesGcm(nextBytes(32))
  private lateinit var result256: ByteArray

  private val associatedData = nextBytes(16)

  @Setup
  fun setup() = runTest {
    data = Random.nextBytes(factor)
    result128 = aesGcm128.encrypt(data, associatedData)
    result256 = aesGcm256.encrypt(data, associatedData)
  }

  @Benchmark
  fun encrypt128() = runTest {
    aesGcm128.encrypt(data, associatedData)
  }

  @Benchmark
  fun decrypt128() = runTest {
    aesGcm128.decrypt(result128, associatedData)
  }

  @Benchmark
  fun encrypt256() = runTest {
    aesGcm256.encrypt(data, associatedData)
  }

  @Benchmark
  fun decrypt256() = runTest {
    aesGcm256.decrypt(result256, associatedData)
  }
}
