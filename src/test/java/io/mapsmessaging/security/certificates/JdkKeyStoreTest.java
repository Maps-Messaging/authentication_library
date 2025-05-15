/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.certificates;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.certificates.jvm.JvmKeyStoreManager;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class JdkKeyStoreTest {

  @Test
  void createTest() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    ConfigurationProperties config = new ConfigurationProperties();
    config.put("passphrase", "changeit");
    CertificateManager manager = CertificateManagerFactory.getInstance().getManager(config);
    Assertions.assertNotNull(manager);
    Assertions.assertInstanceOf(JvmKeyStoreManager.class, manager);
    Assertions.assertTrue(manager.getExists());
  }


  @Test
  void invalidConfig(){
    ConfigurationProperties config = new ConfigurationProperties();
    Assertions.assertThrowsExactly(IOException.class, () -> {CertificateManagerFactory.getInstance().getManager(config);});
  }

  @Test
  void retrieveCertificate()throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException  {
    ConfigurationProperties config = new ConfigurationProperties();
    config.put("passphrase", "changeit");
    CertificateManager manager = CertificateManagerFactory.getInstance().getManager(config);
    List<String> aliases = manager.getAliases();
    Assertions.assertNotNull(aliases);
    Assertions.assertFalse(aliases.isEmpty());
    Assertions.assertNotNull(manager.getCertificate(aliases.get(0)));

    Assertions.assertThrowsExactly(CertificateException.class, () -> manager.getCertificate("Not Real Alias"));
  }

  @Test
  void retrievePrivateKey()throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException  {
    ConfigurationProperties config = new ConfigurationProperties();
    config.put("passphrase", "changeit");
    CertificateManager manager = CertificateManagerFactory.getInstance().getManager(config);
    Assertions.assertThrowsExactly(CertificateException.class, () -> manager.getKey("Not Real Alias", new char[0]));
  }

  @Test
  void ensureExceptionsAreRaised()throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException  {
    ConfigurationProperties config = new ConfigurationProperties();
    config.put("passphrase", "changeit");
    CertificateManager manager = CertificateManagerFactory.getInstance().getManager(config);
    Assertions.assertThrowsExactly(CertificateException.class, () -> {manager.addCertificate("alais", null);});
    Assertions.assertThrowsExactly(CertificateException.class, () -> {manager.deleteCertificate("alais");});
    Assertions.assertThrowsExactly(CertificateException.class, () -> {manager.addPrivateKey("alais", null, null, null);});
  }
}
