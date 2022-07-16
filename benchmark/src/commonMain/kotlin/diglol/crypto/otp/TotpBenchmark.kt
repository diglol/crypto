package diglol.crypto.otp

import diglol.crypto.Hmac
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
class TotpBenchmark {
  @Param("SHA1", "SHA256", "SHA384", "SHA512")
  var factor = ""

  private lateinit var totp: Totp
  private lateinit var result: String

  private val counter = 102400L

  @Setup
  fun setup() = runTest {
    val keySize = when (factor) {
      "SHA1" -> 20
      "SHA256" -> 32
      "SHA384" -> 48
      "SHA512" -> 64
      else -> 20
    }
    totp = Totp(Hmac.Type.valueOf(factor), nextBytes(keySize))
    result = totp.generate(counter)
  }

  @Benchmark
  fun generate() = runTest {
    totp.generate()
  }

  @Benchmark
  fun verify() = runTest {
    totp.verify(result, counter)
  }
}
