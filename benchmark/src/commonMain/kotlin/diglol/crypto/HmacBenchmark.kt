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
class HmacBenchmark {
  @Param("1024", "10240", "102400")
  var factor = 0
  private lateinit var data: ByteArray

  private val hmacSha1 = Hmac(Hmac.Type.SHA1, nextBytes(20))
  private lateinit var resultSha1: ByteArray
  private val hmacSha256 = Hmac(Hmac.Type.SHA256, nextBytes(32))
  private lateinit var resultSha256: ByteArray
  private val hmacSha384 = Hmac(Hmac.Type.SHA256, nextBytes(48))
  private lateinit var resultSha384: ByteArray
  private val hmacSha512 = Hmac(Hmac.Type.SHA256, nextBytes(64))
  private lateinit var resultSha512: ByteArray

  @Setup
  fun setup() = runTest {
    data = Random.nextBytes(factor)
    resultSha1 = hmacSha1.compute(data)
    resultSha256 = hmacSha256.compute(data)
    resultSha384 = hmacSha384.compute(data)
    resultSha512 = hmacSha512.compute(data)
  }

  @Benchmark
  fun computeSha1() = runTest {
    hmacSha1.compute(data)
  }

  @Benchmark
  fun verifySha1() = runTest {
    hmacSha1.verify(resultSha1, data)
  }

  @Benchmark
  fun computeSha256() = runTest {
    hmacSha256.compute(data)
  }

  @Benchmark
  fun verifySha256() = runTest {
    hmacSha256.verify(resultSha256, data)
  }

  @Benchmark
  fun computeSha384() = runTest {
    hmacSha384.compute(data)
  }

  @Benchmark
  fun verifySha384() = runTest {
    hmacSha384.verify(resultSha384, data)
  }

  @Benchmark
  fun computeSha512() = runTest {
    hmacSha512.compute(data)
  }

  @Benchmark
  fun verifySha512() = runTest {
    hmacSha512.verify(resultSha512, data)
  }
}
