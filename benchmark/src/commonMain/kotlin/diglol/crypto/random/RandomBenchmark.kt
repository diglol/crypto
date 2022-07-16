package diglol.crypto.random

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.BenchmarkMode
import kotlinx.benchmark.BenchmarkTimeUnit
import kotlinx.benchmark.Measurement
import kotlinx.benchmark.Mode
import kotlinx.benchmark.OutputTimeUnit
import kotlinx.benchmark.Param
import kotlinx.benchmark.Scope
import kotlinx.benchmark.State
import kotlinx.coroutines.test.runTest

@State(Scope.Benchmark)
@Measurement(iterations = 5, time = 1)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(BenchmarkTimeUnit.MICROSECONDS)
class RandomBenchmark {
  @Param("1024", "10240", "102400")
  var factor = 0

  @Benchmark
  fun nextInt() = runTest {
    nextInt(factor)
  }

  @Benchmark
  fun nextBytes() = runTest {
    nextBytes(factor)
  }
}
