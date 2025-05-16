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

package io.mapsmessaging.security.ssl;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.certificates.BaseCertificateTest;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SslHelperTest extends BaseCertificateTest {
  Logger logger = LoggerFactory.getLogger("SslHelperTest");

  @Test
  void simpleHelperTest() throws Exception {
    setUp("JKS", "file");
    addCert(certificateManager);
    ConfigurationProperties keyStoreProps = new ConfigurationProperties();
    keyStoreProps.put("alias",TEST_ALIAS );
    keyStoreProps.put("type", "JKS");
    keyStoreProps.put("store_passphrase", KEYSTORE_PASSWORD);
    keyStoreProps.put("passphrase", new String(KEY_PASSWORD));
    keyStoreProps.put("path", "./testkeystore.JKS");
    keyStoreProps.put("managerFactory", "SunX509");
    ConfigurationProperties properties = new ConfigurationProperties();
    properties.put("keyStore", keyStoreProps);
    properties.put("trustStore", keyStoreProps);
    properties.put("crlUrl", "http://crls.pki.goog/gts1c3/zdATt0Ex_Fk.crl");
    properties.put("crlInterval", "360000");
    SSLContext sslContext = SslHelper.createContext("TLSv1.3", properties, logger);
    Assertions.assertNotNull(sslContext);

    SSLEngine sslEngine = SslHelper.createSSLEngine(sslContext, new ConfigurationProperties() );
    Assertions.assertNotNull(sslEngine);
  }
}
