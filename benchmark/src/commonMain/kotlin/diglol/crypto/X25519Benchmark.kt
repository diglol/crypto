package diglol.crypto

import diglol.crypto.random.nextBytes
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.BenchmarkMode
import kotlinx.benchmark.BenchmarkTimeUnit
import kotlinx.benchmark.Measurement
import kotlinx.benchmark.Mode
import kotlinx.benchmark.OutputTimeUnit
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.coroutines.test.runTest

@State(Scope.Benchmark)
@Measurement(iterations = 5, time = 1)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(BenchmarkTimeUnit.MICROSECONDS)
class X25519Benchmark {
  private lateinit var keyPair1: KeyPair
  private lateinit var keyPair2: KeyPair

  @Setup
  fun setup() = runTest {
    keyPair1 = X25519.generateKeyPair(nextBytes(32))
    keyPair2 = X25519.generateKeyPair(nextBytes(32))
  }

  @Benchmark
  fun generateKeyPairWithPrivateKey() = runTest {
    X25519.generateKeyPair(keyPair1.privateKey)
  }

  @Benchmark
  fun compute() = runTest {
    X25519.compute(keyPair1.privateKey, keyPair2.publicKey)
  }
}
