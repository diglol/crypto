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
class XChaCha20Benchmark {
  @Param("1024", "10240", "102400")
  var dataSize = 0
  private lateinit var data: ByteArray

  private val xChaCha20 = XChaCha20(nextBytes(32))
  private lateinit var result: ByteArray

  @Setup
  fun setup() = runTest {
    data = Random.nextBytes(dataSize)
    result = xChaCha20.encrypt(data)
  }

  @Benchmark
  fun encrypt() = runTest {
    xChaCha20.encrypt(data)
  }

  @Benchmark
  fun decrypt() = runTest {
    xChaCha20.decrypt(result)
  }
}
