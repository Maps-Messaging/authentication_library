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

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import org.bouncycastle.operator.OperatorCreationException;

public class BaseCertificateTest {

  protected static final String KEYSTORE_PATH = "./testkeystore.jks";
  protected static final char[] KEYSTORE_PASSWORD = "testpassword".toCharArray();
  protected static final String TEST_ALIAS = "testalias";
  protected static final char[] KEY_PASSWORD = "testalias_key".toCharArray();

  protected static CertificateUtils.CertificateWithPrivateKey addCert(
      CertificateManager certificateManager)
      throws CertificateException, IOException, OperatorCreationException {
    return addCert(certificateManager, TEST_ALIAS, KEY_PASSWORD);
  }

  protected static void addMultiCertificates(CertificateManager certificateManager)
      throws CertificateException, IOException, OperatorCreationException {
    for (int x = 0; x < 100; x++) {
      addCert(
          certificateManager,
          TEST_ALIAS + "_" + x,
          (new String(KEY_PASSWORD) + "_" + x).toCharArray());
    }
  }

  protected static CertificateUtils.CertificateWithPrivateKey addCert(
      CertificateManager certificateManager, String alias, char[] password)
      throws CertificateException, IOException, OperatorCreationException {
    CertificateUtils.CertificateWithPrivateKey testCert =
        CertificateUtils.generateSelfSignedCertificateSecret("Testing.fred.org");
    certificateManager.addCertificate(alias, testCert.getCertificate());
    certificateManager.addPrivateKey(
        alias, password, testCert.getPrivateKey(), new Certificate[] {testCert.getCertificate()});
    return testCert;
  }
}
