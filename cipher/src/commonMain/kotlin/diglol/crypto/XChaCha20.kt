package diglol.crypto

import diglol.crypto.internal.toByteArray
import diglol.crypto.internal.toInt
import diglol.crypto.random.nextBytes
import kotlin.jvm.JvmOverloads

// https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-01
// https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/subtle/XChaCha20.java
class XChaCha20 @JvmOverloads constructor(
  key: ByteArray,
  private val nonce: ByteArray? = null,
  private val initialCounter: Int = 1,
) : Cipher {
  private val keyInts: IntArray

  init {
    if (key.size != KEY_SIZE) {
      throw Error("The key length in bytes must be 32")
    }
    if (nonce != null && nonce.size != NONCE_SIZE) {
      throw Error("Nonce length in bytes must be 32")
    }
    keyInts = key.toIntArray()
  }

  override suspend fun encrypt(plaintext: ByteArray): ByteArray {
    if (plaintext.size > Int.MAX_VALUE - NONCE_SIZE) {
      throw Error("Plaintext too long")
    }
    val realNonce = nonce ?: nextBytes(NONCE_SIZE)
    return realNonce + process(realNonce, plaintext)
  }

  override suspend fun decrypt(ciphertext: ByteArray): ByteArray {
    if (ciphertext.size < NONCE_SIZE) {
      throw Error("Ciphertext too short")
    }
    val nonce = ciphertext.copyOf(NONCE_SIZE)
    val rawCiphertext = ciphertext.copyOfRange(NONCE_SIZE, ciphertext.size)
    return process(nonce, rawCiphertext)
  }

  private fun process(nonce: ByteArray, data: ByteArray): ByteArray {
    val out = ByteArray(data.size)
    val numBlocks: Int = data.size / BLOCK_SIZE + 1
    for (i in 0 until numBlocks) {
      val keyBytesBlock = chacha20Block(nonce, i + initialCounter)
      val offset = i * BLOCK_SIZE
      val bytesBlock = if (i == numBlocks - 1) {
        // last block
        xor(data, offset, keyBytesBlock, data.size % BLOCK_SIZE)
      } else {
        xor(data, offset, keyBytesBlock, BLOCK_SIZE)
      }
      bytesBlock.copyInto(out, offset, 0, bytesBlock.size)
    }
    return out
  }

  fun chacha20Block(nonce: ByteArray, counter: Int): ByteArray {
    val state = createInitialState(nonce.toIntArray(), counter)
    val workingState: IntArray = state.copyOf()
    shuffleState(workingState)
    for (i in state.indices) {
      state[i] += workingState[i]
    }
    return state.toByteArray()
  }

  private fun createInitialState(nonce: IntArray, counter: Int): IntArray {
    if (nonce.size != NONCE_SIZE / 4) {
      throw Error("XChaCha20 uses 192-bit nonces, but got a ${nonce.size * 32}-bit nonce")
    }
    // Set the initial state based on https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.3.
    val state = IntArray(BLOCK_INTS_SIZE)
    setSigmaAndKey(state, hChaCha20(keyInts, nonce))
    state[12] = counter
    state[13] = 0
    state[14] = nonce[4]
    state[15] = nonce[5]
    return state
  }

  companion object {
    const val BLOCK_INTS_SIZE = 16
    const val BLOCK_SIZE = BLOCK_INTS_SIZE * 4
    const val KEY_INTS_SIZE = 8
    const val KEY_SIZE = KEY_INTS_SIZE * 4
    const val NONCE_SIZE = 24

    // bytesToInts 'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    private val SIGMA: IntArray = intArrayOf(1634760805, 857760878, 2036477234, 1797285236)

    private fun hChaCha20(key: IntArray, nonce: IntArray): IntArray {
      val state = IntArray(BLOCK_INTS_SIZE)
      setSigmaAndKey(state, key)
      state[12] = nonce[0]
      state[13] = nonce[1]
      state[14] = nonce[2]
      state[15] = nonce[3]
      shuffleState(state)
      // state[0] = state[0], state[1] = state[1], state[2] = state[2], state[3] = state[3]
      state[4] = state[12]
      state[5] = state[13]
      state[6] = state[14]
      state[7] = state[15]
      return state.copyOf(KEY_INTS_SIZE)
    }

    private fun setSigmaAndKey(state: IntArray, key: IntArray) {
      SIGMA.copyInto(state, 0, 0, SIGMA.size)
      key.copyInto(state, SIGMA.size, 0, KEY_INTS_SIZE)
    }

    private fun shuffleState(state: IntArray) {
      for (i in 0..9) {
        quarterRound(state, 0, 4, 8, 12)
        quarterRound(state, 1, 5, 9, 13)
        quarterRound(state, 2, 6, 10, 14)
        quarterRound(state, 3, 7, 11, 15)
        quarterRound(state, 0, 5, 10, 15)
        quarterRound(state, 1, 6, 11, 12)
        quarterRound(state, 2, 7, 8, 13)
        quarterRound(state, 3, 4, 9, 14)
      }
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
      x[a] += x[b]
      x[d] = rotateLeft(x[d] xor x[a], 16)
      x[c] += x[d]
      x[b] = rotateLeft(x[b] xor x[c], 12)
      x[a] += x[b]
      x[d] = rotateLeft(x[d] xor x[a], 8)
      x[c] += x[d]
      x[b] = rotateLeft(x[b] xor x[c], 7)
    }

    private fun rotateLeft(x: Int, y: Int): Int {
      return x shl y or (x ushr -y)
    }

    private fun ByteArray.toIntArray(): IntArray {
      val size = size / 4
      val ints = IntArray(size)
      for (i in 0 until size) {
        val startIdx = i * 4
        ints[i] = copyOfRange(startIdx, startIdx + 4).toInt(false)!!
      }
      return ints
    }

    private fun IntArray.toByteArray(): ByteArray {
      val bytes = ByteArray(size * 4)
      for (i in indices) {
        this[i].toByteArray(false).copyInto(bytes, i * 4, 0, 4)
      }
      return bytes
    }

    private fun xor(x: ByteArray, xStartIndex: Int, y: ByteArray, len: Int): ByteArray {
      if (len < 0 || x.size < len || y.size < len) {
        throw Error("That combination of buffers, offsets and length to xor result in out-of-bond accesses.")
      }
      val res = ByteArray(len)
      for (i in 0 until len) {
        res[i] = ((x[xStartIndex + i].toInt() xor y[i].toInt())).toByte()
      }
      return res
    }
  }
}
