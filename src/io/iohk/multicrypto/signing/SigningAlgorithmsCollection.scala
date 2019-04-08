package io.iohk.multicrypto
package signing

import java.security.SecureRandom

import enumeratum._

class SigningAlgorithmsCollection(secureRandom: SecureRandom) {

  sealed abstract class SigningAlgorithmType(private[multicrypto] val algorithm: SigningAlgorithm) extends EnumEntry {
    def algorithmIdentifier = entryName
  }

  object SigningAlgorithmType extends Enum[SigningAlgorithmType] {

    val values = findValues

    case object SHA256withRSA extends SigningAlgorithmType(new algorithms.SHA256withRSA(secureRandom))
  }

  def apply(identifier: String): Option[SigningAlgorithmType] =
    SigningAlgorithmType.withNameOption(identifier)

  def fromPublicKey(obj: AnyRef): Option[SigningAlgorithmType] = {
    SigningAlgorithmType.values
      .find(_.algorithm.toPublicKey(obj).isDefined)
  }

  def fromPrivateKey(obj: AnyRef): Option[SigningAlgorithmType] = {
    SigningAlgorithmType.values
      .find(_.algorithm.toPrivateKey(obj).isDefined)
  }
}

object SigningAlgorithmsCollection {
  def apply(secureRandom: SecureRandom): SigningAlgorithmsCollection = new SigningAlgorithmsCollection(secureRandom)
}
