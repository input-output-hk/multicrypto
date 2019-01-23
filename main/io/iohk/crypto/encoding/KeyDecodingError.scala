package io.iohk.crypto.encoding

sealed trait KeyDecodingError

object KeyDecodingError {
  case class UnderlayingImplementationError(description: String) extends KeyDecodingError
}
