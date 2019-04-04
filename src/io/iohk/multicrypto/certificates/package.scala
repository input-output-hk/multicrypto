package io.iohk.multicrypto

import java.security.cert._
import javax.naming.ldap.LdapName

import scala.collection.JavaConverters.asScalaBufferConverter

import io.iohk.decco._
import io.iohk.decco.auto._
import java.io.ByteArrayInputStream
import scala.util.Try

package object certificates {

  implicit class X509CertificateExt(inner: X509Certificate) {

    def commonName: Option[String] = {
      val distinguishedName = inner.getSubjectX500Principal.getName
      extractCommonName(distinguishedName)
    }

    def signingPublicKey: Option[SigningPublicKey] = {
      toSigningPublicKey(inner.getPublicKey)
    }
  }

  private def extractCommonName(distinguishedName: String): Option[String] = {
    val ldapDN = new LdapName(distinguishedName)
    val commonName = ldapDN.getRdns.asScala
      .find(_.getType equalsIgnoreCase "cn")

    commonName
      .map(_.getValue.toString.trim)
      .filter(_.nonEmpty)
  }

  private val factory = CertificateFactory.getInstance("X.509")

  implicit val x509Codec: PartialCodec[X509Certificate] =
    PartialCodec[Array[Byte]]
      .mapOpt(
        ba =>
          Try {
            factory.generateCertificate(new ByteArrayInputStream(ba)).asInstanceOf[X509Certificate]
          }.toOption,
        _.getEncoded
      )

}
