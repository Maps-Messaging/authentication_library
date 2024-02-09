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

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Pkcs11ManagerTest extends BaseCertificateTest {

  @BeforeEach
  void setUp() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    File file = new File(".");
    System.err.println(file.getAbsolutePath());
    Map<String, String> config = new LinkedHashMap<>();
    config.put("configPath", "./softhsm.cfg");
    config.put("type", "pkcs11");
    config.put("passphrase", "123456");
    config.put("providerName", "SunPKCS11");
    certificateManager = CertificateManagerFactory.getInstance().getManager(config);
  }

  @Test
  void testAddAndGetCertificate() throws Exception {
    File file = new File("./softhsm.cfg");
    Assertions.assertTrue(file.exists(), "Should be able to locate softhsm to test");
    setUp();
  }

}
