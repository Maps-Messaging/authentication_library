/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import io.mapsmessaging.configuration.ConfigurationProperties;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Pkcs11ManagerTest extends BaseCertificateTest {

  @BeforeEach
  void setUp() {
    File configFile = new File("./softhsm.cfg");
    Assumptions.assumeTrue(configFile.isFile(), "SoftHSM configuration is not available");

    Map<String, Object> config = new LinkedHashMap<>();
    config.put("configPath", configFile.getPath());
    config.put("type", "pkcs11");
    config.put("passphrase", "1234");
    config.put("providerName", "SunPKCS11");

    try {
      certificateManager = CertificateManagerFactory.getInstance().getManager(new ConfigurationProperties(config));
    } catch (Exception exception) {
      Assumptions.assumeTrue(false, "PKCS#11 provider is not available: " + exception.getMessage());
    }

    Assumptions.assumeTrue(certificateManager != null, "PKCS#11 provider is not available");
  }

  @Test
  void testAddAndGetCertificate() {
    Assertions.assertNotNull(certificateManager);
  }

  @Test
  void signsWithRetrievedEd25519ProviderKeyWhenSupported() throws Exception {
    Provider provider = certificateManager.getKeyStore().getProvider();
    KeyPairGenerator generator;
    try {
      generator = KeyPairGenerator.getInstance("Ed25519", provider);
      Signature.getInstance("Ed25519", provider);
    } catch (NoSuchAlgorithmException unsupported) {
      Assumptions.abort("PKCS#11 provider does not expose Ed25519: " + provider.getName());
      return;
    }
    KeyPair keyPair = generator.generateKeyPair();
    X500Principal subject = new X500Principal("CN=pkcs11-ed25519-test");
    Date notBefore = new Date();
    Date notAfter = new Date(notBefore.getTime() + 86_400_000L);
    JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, notBefore, notAfter, subject, keyPair.getPublic());
    byte[] encoded = builder.build(new JcaContentSignerBuilder("Ed25519").setProvider(provider).build(keyPair.getPrivate())).getEncoded();
    Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));
    String alias = "ed25519-test-" + UUID.randomUUID();
    try {
      // Token entries persist through the provider; no stream save or private-key encoding is involved.
      certificateManager.getKeyStore().setKeyEntry(alias, keyPair.getPrivate(), null, new Certificate[] {certificate});
      PrivateKey retrieved = certificateManager.getKey(alias, null);
      Signature signer = Signature.getInstance("Ed25519", provider);
      byte[] challenge = "provider-backed challenge".getBytes(StandardCharsets.UTF_8);
      signer.initSign(retrieved);
      signer.update(challenge);
      byte[] signature = signer.sign();
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(certificateManager.getCertificate(alias).getPublicKey());
      verifier.update(challenge);
      Assertions.assertTrue(verifier.verify(signature));
    } finally {
      certificateManager.getKeyStore().deleteEntry(alias);
    }
  }
}
