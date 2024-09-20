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

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.jaas.PropertiesLoader;
import java.io.File;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.stream.Stream;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.params.provider.Arguments;

public class BaseCertificateTest {

  protected static final String KEYSTORE_PATH = "./testkeystore";
  protected static final String KEYSTORE_PASSWORD = "testpassword";
  protected static final String TEST_ALIAS = "testalias";
  protected static final char[] KEY_PASSWORD = "testalias_key".toCharArray();

  private static final int counter = 0;

  protected CertificateManager certificateManager;

  static Stream<Arguments> knownTypes() {
    List<Arguments> argumentsList = new ArrayList<>();
    String[] types = {"JKS", "PKCS12", "JCEKS", "BKS", "UBER"};
    String[] stores = {"file", "vault"};
    for (String store : stores) {
      for (String type : types) {
        argumentsList.add(Arguments.of(type, store));
      }
    }
    return argumentsList.stream();
  }


  protected void setUp(String type, String store) throws Exception {
    File file = new File(KEYSTORE_PATH + "." + type);
    file.delete();
    certificateManager = createManager(type, store);
  }


  protected CertificateManager createManager(String type, String store) throws Exception {
    File file = new File(KEYSTORE_PATH + "." + type);
    Map<String, Object> config = new LinkedHashMap<>();
    config.put("path", file.getName());
    config.put("store", store);
    config.put("passphrase", KEYSTORE_PASSWORD);
    if (type.equals("BKS") || type.equals("UBER")) {
      config.put("providerName", "BC");
    }
    config.put("type", type);
    if(store.equals("vault")){
      Properties properties = PropertiesLoader.getProperties("vault.properties");
      for(Map.Entry<Object, Object> entry:properties.entrySet()){
        config.put(entry.getKey().toString(), entry.getValue().toString());
      }
    }
    return CertificateManagerFactory.getInstance().getManager(new ConfigurationProperties(config));
  }

  protected static CertificateWithPrivateKey addCert(CertificateManager certificateManager)
      throws CertificateException, IOException, OperatorCreationException {
    return addCert(certificateManager, TEST_ALIAS, KEY_PASSWORD);
  }

  protected static void addMultiCertificates(CertificateManager certificateManager)
      throws CertificateException, IOException, OperatorCreationException {
    for (int x = 0; x < 10; x++) {
      addCert(
          certificateManager,
          TEST_ALIAS + "_" + x,
          (new String(KEY_PASSWORD) + "_" + x).toCharArray());
    }
  }

  protected static CertificateWithPrivateKey addCert(CertificateManager certificateManager, String alias, char[] password)
      throws CertificateException, IOException, OperatorCreationException {
    CertificateWithPrivateKey testCert = CertificateUtils.generateSelfSignedCertificateSecret("Testing.fred.org");
    certificateManager.addCertificate(alias, testCert.getCertificate());
    certificateManager.addPrivateKey(alias, password, testCert.getPrivateKey(), new Certificate[] {testCert.getCertificate()});
    return testCert;
  }
}
