package io.iohk.multicrypto

import io.iohk.multicrypto.hashing.HashingAlgorithmsCollection
import io.iohk.multicrypto.hashing.HashBytes
import io.iohk.multicrypto.encoding.TypedByteString
import io.iohk.decco.Codec
import io.iohk.multicrypto.encoding._
import io.iohk.multicrypto.encoding.implicits._

trait Hashing {

  // PARAMETERS
  protected val hashingCollection: HashingAlgorithmsCollection
  protected val hashingType: hashingCollection.HashingAlgorithmType

  /**
    * Generates a hash for `entity`, using the default hashing algorithm
    *
    * @tparam T        the type of `entity`
    *
    * @param  entity   the entity that needs to be hashed
    * @param  codec  how to convert `entity` into a stream of bytes
    *
    * @return          a hash of `entity`
    */
  def hash[T](entity: T)(implicit codec: Codec[T]): Hash =
    new Hash(hashingType, hashingType.algorithm.hash(codec.encode(entity)))

  /**
    * Returns `true` if `hash` is a hash of `entity`, when using the hashing algorithm
    * encoded in `hash`
    *
    * @tparam T          the type of `entity`
    *
    * @param  entity     the entity that needs to be checked
    * @param  hash       the hash that needs to be checked. It also identifies the
    *                    hashing algorithm to use
    * @param  codec    how to convert `entity` into a stream of bytes
    *
    * @return            `true` if `hash` is a valid hash of `entity`
    */
  def isValidHash[T](entity: T, hash: Hash)(implicit codec: Codec[T]): Boolean =
    hash.`type`.algorithm.hash(codec.encode(entity)) == hash.bytes

  /** Data entity containing a hash and the identifier of the hashing algorithm used to generate it */
  class Hash(private[Hashing] val `type`: hashingCollection.HashingAlgorithmType, private[Hashing] val bytes: HashBytes)
      extends CryptoEntity[Hash, Hash.type] {

    private[multicrypto] val companion: Hash.type = Hash
    protected val self: Hash = this

    override def equals(obj: scala.Any): Boolean = obj match {
      case that: Hash => `type` == that.`type` && bytes == that.bytes
      case _ => false
    }
  }

  object Hash extends CryptoEntityCompanion[Hash] {

    override protected val title: String = "HASH"

    private[multicrypto] def encodeInto(hash: Hash): TypedByteString =
      TypedByteString(hash.`type`.algorithmIdentifier, hash.bytes.bytes)

    private[multicrypto] def decodeFrom(tbs: TypedByteString): Either[DecodeError[Hash], Hash] = {
      hashingCollection(tbs.`type`) match {
        case Some(hashingType) =>
          Right(new Hash(hashingType, HashBytes(tbs.bytes)))
        case None =>
          Left(DecodeError.UnsupportedAlgorithm(tbs.`type`))
      }
    }
  }

}
