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
class EncryptThenMacBenchmark {
  @Param("1024", "10240", "102400")
  var factor = 0
  private lateinit var data: ByteArray

  private lateinit var encryptThenMac: EncryptThenMac
  private lateinit var associatedData: ByteArray
  private lateinit var result: ByteArray

  @Setup
  fun setup() = runTest {
    data = Random.nextBytes(factor)
    encryptThenMac = EncryptThenMac(AesCbc(nextBytes(32)), Hmac(Hmac.Type.SHA256, nextBytes(32)))
    associatedData = nextBytes(16)
    result = encryptThenMac.encrypt(data, associatedData)
  }

  @Benchmark
  fun encryptAesCbcHmac256() = runTest {
    encryptThenMac.encrypt(data, associatedData)
  }

  @Benchmark
  fun decryptAesCbcHmac256() = runTest {
    encryptThenMac.decrypt(result, associatedData)
  }
}
