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

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.certificates.keystore.KeyStoreManager;
import java.io.File;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import org.junit.jupiter.api.*;

class KeyStoreManagerTest extends BaseCertificateTest {

  private KeyStoreManager certificateManager;

  @BeforeEach
  void setUp() throws Exception {
    File file = new File(KEYSTORE_PATH);
    file.delete();
    certificateManager = new KeyStoreManager(KEYSTORE_PATH, KEYSTORE_PASSWORD);
  }

  @Test
  void testAddAndGetCertificate() throws Exception {
    CertificateUtils.CertificateWithPrivateKey testCert = addCert(certificateManager);
    Certificate retrievedCert = certificateManager.getCertificate(TEST_ALIAS);
    assertNotNull(retrievedCert, "Certificate should not be null");
    assertEquals(
        testCert.getCertificate(),
        retrievedCert,
        "Retrieved certificate should match the original");
  }

  @Test
  void testInvalidAliasCertificate() throws Exception {
    assertThrows(
        CertificateException.class,
        () -> certificateManager.getCertificate(TEST_ALIAS),
        "Should throw an exception when trying to retrieve a deleted certificate");
  }

  @Test
  void testGetKey() throws Exception {
    CertificateUtils.CertificateWithPrivateKey testCert = addCert(certificateManager);
    PrivateKey retrievedKey = certificateManager.getKey(TEST_ALIAS, KEY_PASSWORD);
    assertNotNull(retrievedKey, "Private key should not be null");
    assertEquals(
        testCert.getPrivateKey(), retrievedKey, "Retrieved private keys should match the original");
  }
}
