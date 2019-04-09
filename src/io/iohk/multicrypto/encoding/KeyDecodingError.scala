package io.iohk.multicrypto.encoding

sealed trait KeyDecodingError

object KeyDecodingError {
  case class UnderlayingImplementationError(description: String) extends KeyDecodingError
}
