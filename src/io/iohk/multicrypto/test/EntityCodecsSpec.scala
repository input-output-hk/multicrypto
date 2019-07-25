package io.iohk.multicrypto

 import io.iohk.decco.auto._
 import org.scalatest.FlatSpec
 import io.iohk.multicrypto.encoding.TypedByteString
 import io.iohk.multicrypto.test.utils.CryptoEntityArbitraries
 import io.iohk.decco.test.utils.CodecTestingHelpers

 class EntityCodecsSpec extends FlatSpec with CodecTestingHelpers with CryptoEntityArbitraries {

   behavior of "CryptoEntities Codecs"

   it should "work correctly with TypedByteString" in { testCodec[TypedByteString] }
   it should "work correctly with SigningPublicKey" in { testCodec[SigningPublicKey] }
   it should "work correctly with SigningPrivateKey" in { testCodec[SigningPrivateKey] }
   it should "work correctly with SigningKeyPair" in { testCodec[SigningKeyPair] }
   it should "work correctly with EncryptionPublicKey" in { testCodec[EncryptionPublicKey] }
   it should "work correctly with EncryptionPrivateKey" in { testCodec[EncryptionPrivateKey] }
   it should "work correctly with EncryptionKeyPair" in { testCodec[EncryptionKeyPair] }
   it should "work correctly with Hash" in { testCodec[Hash] }
   it should "work correctly with Signature" in { testCodec[Signature] }
   it should "work correctly with EncryptedData" in { testCodec[EncryptedData] }

 }
