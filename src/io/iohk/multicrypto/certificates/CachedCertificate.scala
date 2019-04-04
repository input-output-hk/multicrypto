package io.iohk.multicrypto.certificates

import java.security.cert.X509Certificate

import io.iohk.multicrypto._

/**
  * The Java X509Certificate is complex. It isn't simple to extract the information that we need from it.
  *
  * While using the helper methods from the [[X509CertificateExt]] can simplify this, it would require us to validate
  * the data on every usage which is tedious.
  *
  * Instead, the used data is cached into this case class, which means that the data is already validated, hence,
  * the [[identity]] and [[publicKey]] are exactly what you can retrieve from the [[x509]] certificate.
  */
class CachedCertificate private (
    val identity: String,
    val publicKey: SigningPublicKey,
    private[certificates] val x509: X509Certificate
) {

  override def equals(obj: scala.Any): Boolean = obj match {
    case that: CachedCertificate =>
      identity == that.identity &&
        publicKey == that.publicKey &&
        x509 == that.x509

    case _ => false
  }

  override def toString: String = s"CachedCertificate($identity)"
}

object CachedCertificate {

  def from(identity: String, publicKey: SigningPublicKey, x509: X509Certificate): Option[CachedCertificate] = {
    for {
      x509Identity <- x509.commonName if identity == x509Identity
      x509PublicKey <- x509.signingPublicKey if publicKey == x509PublicKey
    } yield new CachedCertificate(identity, publicKey, x509) {}
  }

  def from(x509: X509Certificate): Option[CachedCertificate] = {
    for {
      x509Identity <- x509.commonName
      x509PublicKey <- x509.signingPublicKey
    } yield new CachedCertificate(x509Identity, x509PublicKey, x509)
  }

}
