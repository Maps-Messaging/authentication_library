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

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class KeyStoreManagerTest extends BaseCertificateTest {

  @ParameterizedTest
  @MethodSource("knownTypes")
  void testAddAndGetCertificate(String type) throws Exception {
    setUp(type);
    CertificateWithPrivateKey testCert = addCert(certificateManager);
    Certificate retrievedCert = certificateManager.getCertificate(TEST_ALIAS);
    assertNotNull(retrievedCert, "Certificate should not be null");
    assertEquals(
        testCert.getCertificate(),
        retrievedCert,
        "Retrieved certificate should match the original");
  }

  @ParameterizedTest
  @MethodSource("knownTypes")
  void testInvalidAliasCertificate(String type) throws Exception {
    setUp(type);

    assertThrows(
        CertificateException.class,
        () -> certificateManager.getCertificate(TEST_ALIAS),
        "Should throw an exception when trying to retrieve a deleted certificate");
  }

  @ParameterizedTest
  @MethodSource("knownTypes")
  void testGetKey(String type) throws Exception {
    setUp(type);

    CertificateWithPrivateKey testCert = addCert(certificateManager);
    PrivateKey retrievedKey = certificateManager.getKey(TEST_ALIAS, KEY_PASSWORD);
    assertNotNull(retrievedKey, "Private key should not be null");
    assertEquals(
        testCert.getPrivateKey(), retrievedKey, "Retrieved private keys should match the original");
  }
}
