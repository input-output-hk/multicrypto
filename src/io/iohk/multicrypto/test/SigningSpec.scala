package io.iohk.multicrypto

import akka.util.ByteString
import io.iohk.multicrypto.encoding._
import org.scalatest.EitherValues._
import org.scalatest.MustMatchers._
import org.scalatest.WordSpec
import org.scalatest.prop.PropertyChecks._
import io.iohk.decco.auto._

class SigningSpec extends WordSpec {

  private val keypair1 = generateSigningKeyPair()
  private val keypair2 = generateSigningKeyPair()

  case class User(name: String, age: Int)

  "generateSigningKeyPair" should {
    "generate different key pairs" in {
      keypair1.public must not be keypair2.public
      keypair1.`private` must not be keypair2.`private`
    }
  }

  "sign" should {
    "generate a signature for any Entity input" in {
      forAll { (name: String, age: Int) =>
        val entity = User(name, age)

        val result = sign(entity, keypair1.`private`)

        result.toByteString mustNot be(empty)
      }
    }
  }

  "isValidSignature" should {
    "fail to verify the signature of an entity with the wrong key" in {
      val input = User("name", 12)

      val signature1 = sign(input, keypair1.`private`)
      val signature2 = sign(input, keypair2.`private`)

      isValidSignature(input, signature1, keypair2.public) mustBe false
      isValidSignature(input, signature2, keypair1.public) mustBe false
    }

    "verify the signature of an entity with the right key" in {
      val entity = User("name", 12)

      val signature = sign(entity, keypair1.`private`)

      isValidSignature(entity, signature, keypair1.public) must be(true)
    }
  }

  "Signature.decodeFrom" should {
    "decode valid signature" in {
      val input = User("name", 12)

      val signature = sign(input, keypair1.`private`)
      val result = Signature.decodeFrom(signature.toByteString)

      result.right.value.toByteString.toArray mustNot be(empty)
    }

    "fail to decode invalid signatures" in {
      val bytes = ByteString(randomBytes(1024))
      val result = Signature.decodeFrom(bytes)

      result.isLeft mustBe true
    }

    "fail to decode signatures with unsupported algorithms" in {
      val input = ByteString()
      val algorithm = ByteString("SHA256withRSA".getBytes("UTF-16")).drop(3)

      val signature = sign(input, keypair1.`private`)

      val index = signature.toByteString.indexOfSlice(algorithm)
      val corruptedBytes = signature.toByteString.updated(index, 'X'.toByte)
      val expected = DecodeError.UnsupportedAlgorithm("XHA256withRSA")

      val result = Signature.decodeFrom(corruptedBytes)

      result.left.value must be(expected)
    }
  }

  "SigningPublicKey.decodeFrom" should {
    "decode valid public key" in {
      val key = keypair1.public

      val result = SigningPublicKey.decodeFrom(key.toByteString)

      result.right.value.toByteString.toArray mustNot be(empty)
    }

    "fail to decode invalid public key" in {
      val bytes = ByteString()
      val result = SigningPublicKey.decodeFrom(bytes)

      result.isLeft mustBe true
    }

    "fail to decode public keys with unsupported algorithms" in {
      val algorithm = ByteString("SHA256withRSA".getBytes("UTF-16")).drop(3)
      val key = keypair1.public
      val index = key.toByteString.indexOfSlice(algorithm)
      val corruptedBytes = key.toByteString.updated(index, 'X'.toByte)
      val expected = KeyDecodeError.UnsupportedAlgorithm("XHA256withRSA")

      val result = SigningPublicKey.decodeFrom(corruptedBytes)

      result.left.value must be(expected)
    }
  }

  "SigningPrivateKey.decodeFrom" should {
    "decode valid private key" in {
      val key = keypair1.`private`

      val result = SigningPrivateKey.decodeFrom(key.toByteString)

      result.right.value.toByteString.toArray mustNot be(empty)
    }

    "fail to decode invalid private key" in {
      val bytes = ByteString()
      val result = SigningPrivateKey.decodeFrom(bytes)

      result.isLeft mustBe true
    }

    "fail to decode private keys with unsupported algorithms" in {
      val algorithm = ByteString("SHA256withRSA".getBytes("UTF-16")).drop(3)
      val key = keypair1.`private`
      val index = key.toByteString.indexOfSlice(algorithm)
      val corruptedBytes = key.toByteString.updated(index, 'X'.toByte)
      val expected = KeyDecodeError.UnsupportedAlgorithm("XHA256withRSA")

      val result = SigningPrivateKey.decodeFrom(corruptedBytes)

      result.left.value must be(expected)
    }
  }

  import scala.util.Random
  private def randomBytes(n: Int): Array[Byte] = {
    val a = new Array[Byte](n)
    Random.nextBytes(a)
    a
  }

}
