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
class Poly1305Benchmark {
  @Param("1024", "10240", "102400")
  var factor = 0
  private lateinit var data: ByteArray

  private lateinit var poly1305: Poly1305
  private lateinit var result: ByteArray

  @Setup
  fun setup() = runTest {
    data = Random.nextBytes(factor)
    poly1305 = Poly1305(nextBytes(32))
    result = poly1305.compute(data)
  }

  @Benchmark
  fun compute() = runTest {
    poly1305.compute(data)
  }

  @Benchmark
  fun verify() = runTest {
    poly1305.verify(result, data)
  }
}
