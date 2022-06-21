package diglol.crypto

class Error(message: String?, cause: Throwable?) : kotlin.Error(message, cause) {
  constructor() : this(null, null)
  constructor(message: String?) : this(message, null)
  constructor(cause: Throwable?) : this(null, cause)
}
