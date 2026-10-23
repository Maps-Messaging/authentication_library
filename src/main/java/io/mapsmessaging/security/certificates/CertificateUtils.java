/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.certificates;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.NamedParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HexFormat;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateUtils {

  /** Creates a transport identity certificate, with a positive validity in whole seconds. */
  public static CertificateWithPrivateKey generateEd25519Identity(X500Principal subject, Duration validity)
      throws GeneralSecurityException, OperatorCreationException, IOException {
    if (subject == null || validity == null || validity.isNegative() || validity.isZero() || validity.getNano() != 0) {
      throw new IllegalArgumentException("Subject and a positive validity in whole seconds are required");
    }
    Instant notBefore = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    Date notAfter = Date.from(notBefore.plus(validity));
    SecureRandom random = new SecureRandom();
    KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
    generator.initialize(NamedParameterSpec.ED25519, random);
    KeyPair keyPair = generator.generateKeyPair();
    BigInteger serialNumber;
    do {
      serialNumber = new BigInteger(159, random);
    } while (serialNumber.signum() == 0);
    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        subject, serialNumber, Date.from(notBefore), notAfter, subject, keyPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    ContentSigner signer = new JcaContentSignerBuilder("Ed25519").build(keyPair.getPrivate());
    byte[] encoded = builder.build(signer).getEncoded();
    Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));
    return new CertificateWithPrivateKey(certificate, keyPair.getPrivate());
  }

  /** SHA-256 of the public key's SubjectPublicKeyInfo encoding, in lowercase hexadecimal. */
  public static String publicKeyFingerprint(PublicKey publicKey) throws NoSuchAlgorithmException {
    if (publicKey == null || publicKey.getEncoded() == null) {
      throw new IllegalArgumentException("An encoded public key is required");
    }
    return "SHA-256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
  }

  static PublicKey ed25519PublicKey(Certificate certificate) throws CertificateException {
    if (certificate == null || !"X.509".equalsIgnoreCase(certificate.getType())) {
      throw new CertificateException("An X.509 Ed25519 certificate is required");
    }
    PublicKey publicKey = certificate.getPublicKey();
    requireEd25519PublicKey(publicKey);
    return publicKey;
  }

  static void requireEd25519PublicKey(PublicKey publicKey) throws CertificateException {
    if (publicKey == null || publicKey.getEncoded() == null) {
      throw new CertificateException("An encoded Ed25519 public key is required");
    }
    try {
      SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      // Provider names may be EdDSA for either Ed25519 or Ed448. Pin the actual algorithm OID.
      if (!EdECObjectIdentifiers.id_Ed25519.equals(keyInfo.getAlgorithm().getAlgorithm())) {
        throw new CertificateException("Expected an Ed25519 public key");
      }
    } catch (IllegalArgumentException exception) {
      throw new CertificateException("Invalid public key encoding", exception);
    }
  }

  public static CertificateWithPrivateKey generateSelfSignedCertificateSecret(String host)
      throws OperatorCreationException, IOException, CertificateException {
    Security.addProvider(new BouncyCastleProvider());

    X500Principal subject = new X500Principal("CN=" + host);
    KeyPair keyPair = generateKeyPair();

    long notBefore = System.currentTimeMillis();
    long notAfter = notBefore + (1000L * 3600L * 24 * 365);

    ASN1Encodable[] encodableAltNames =
        new ASN1Encodable[] {new GeneralName(GeneralName.dNSName, host)};
    KeyPurposeId[] purposes =
        new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth};

    X509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.ONE,
            new Date(notBefore),
            new Date(notAfter),
            subject,
            keyPair.getPublic());

    certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    certBuilder.addExtension(
        Extension.keyUsage,
        true,
        new KeyUsage(KeyUsage.digitalSignature + KeyUsage.keyEncipherment));
    certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes));
    certBuilder.addExtension(
        Extension.subjectAlternativeName, false, new DERSequence(encodableAltNames));

    final ContentSigner signer =
        new JcaContentSignerBuilder(("SHA256withRSA")).build(keyPair.getPrivate());

    X509CertificateHolder certHolder = certBuilder.build(signer);

    byte[] x509Encoded = certHolder.toASN1Structure().getEncoded();
    java.security.cert.Certificate certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(x509Encoded));
    PrivateKey privateKey = keyPair.getPrivate();
    return new CertificateWithPrivateKey(certificate, privateKey);
  }

  private static KeyPair generateKeyPair() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048, new SecureRandom());
      return keyPairGenerator.generateKeyPair();
    } catch (GeneralSecurityException var2) {
      throw new AssertionError(var2);
    }
  }

  private CertificateUtils(){}

}
