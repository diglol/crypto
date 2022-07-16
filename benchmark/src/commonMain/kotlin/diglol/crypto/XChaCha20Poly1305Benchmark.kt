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
class XChaCha20Poly1305Benchmark {
  @Param("1024", "10240", "102400")
  var dataSize = 0
  private lateinit var data: ByteArray

  private val xChaCha20Poly1305 = XChaCha20Poly1305(nextBytes(32))
  private lateinit var associatedData: ByteArray
  private lateinit var result: ByteArray

  @Setup
  fun setup() = runTest {
    data = Random.nextBytes(dataSize)
    associatedData = nextBytes(16)
    result = xChaCha20Poly1305.encrypt(data, associatedData)
  }

  @Benchmark
  fun encrypt() = runTest {
    xChaCha20Poly1305.encrypt(data, associatedData)
  }

  @Benchmark
  fun decrypt() = runTest {
    xChaCha20Poly1305.decrypt(result, associatedData)
  }
}
