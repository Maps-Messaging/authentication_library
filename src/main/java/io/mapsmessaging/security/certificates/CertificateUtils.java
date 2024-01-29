/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.certificates;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateUtils {

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
