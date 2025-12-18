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

package io.mapsmessaging.security.certificates.jvm;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.certificates.BaseKeyStoreManager;
import io.mapsmessaging.security.certificates.CertificateManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class JvmKeyStoreManager extends BaseKeyStoreManager {

  protected static final String KEYSTORE_PASSWORD = "passphrase";


  public JvmKeyStoreManager() {
  }

  public boolean isValid(ConfigurationProperties config) {
    return config.containsKey(KEYSTORE_PASSWORD);
  }

  protected JvmKeyStoreManager(ConfigurationProperties config) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    String t = config.getProperty(KEYSTORE_PASSWORD);
    if (t == null) {
      t = "";
    }
    String type = KeyStore.getDefaultType();
    keyStore = KeyStore.getInstance(type);

    // Get path to the JVM's cacerts file
    String javaHome = System.getProperty("java.home");
    String cacertsPath = javaHome + "/lib/security/cacerts";

    try (FileInputStream fis = new FileInputStream(cacertsPath)) {
      keyStore.load(fis, t.toCharArray());
    }
  }

  public CertificateManager create(ConfigurationProperties config) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    return new JvmKeyStoreManager(config);
  }

  @Override
  public void addCertificate(String alias, Certificate certificate) throws CertificateException {
    throw new CertificateException("Unable to add certificates to JVM Key Store");
  }

  @Override
  public void deleteCertificate(String alias) throws CertificateException {
    throw new CertificateException("Unable to delete certificates to JVM Key Store");
  }

  @Override
  public void addPrivateKey(
      String alias, char[] password, PrivateKey privateKey, Certificate[] certChain)
      throws CertificateException {
    throw new CertificateException("Unable to add private key certificates to JVM Key Store");
  }

  @Override
  public boolean getExists() {
    return true;
  }

  @Override
  public void saveKeyStore() throws CertificateException {
    throw new CertificateException("Unable to delete certificates to JVM Key Store");
  }

}
