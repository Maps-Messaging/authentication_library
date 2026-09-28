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
import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
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
}
