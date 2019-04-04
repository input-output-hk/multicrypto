package io.iohk.multicrypto
package hashing

import enumeratum._

class HashingAlgorithmsCollection {

  sealed abstract class HashingAlgorithmType(private[multicrypto] val algorithm: HashAlgorithm) extends EnumEntry {
    def algorithmIdentifier = entryName
  }

  object HashingAlgorithmType extends Enum[HashingAlgorithmType] {

    val values = findValues

    case object SHA256 extends HashingAlgorithmType(algorithms.SHA256)
  }

  def apply(identifier: String): Option[HashingAlgorithmType] =
    HashingAlgorithmType.withNameOption(identifier)
}

object HashingAlgorithmsCollection {
  def apply(): HashingAlgorithmsCollection = new HashingAlgorithmsCollection()
}
