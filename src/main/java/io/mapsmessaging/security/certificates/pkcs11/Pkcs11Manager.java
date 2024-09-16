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

package io.mapsmessaging.security.certificates.pkcs11;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.certificates.keystore.KeyStoreManager;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class Pkcs11Manager extends KeyStoreManager {

  private static final String PKCS11_CONFIG = "configPath";

  public Pkcs11Manager() {
    super();
  }

  protected Pkcs11Manager(ConfigurationProperties config)
      throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    super(config);
  }

  @Override
  public CertificateManager create(ConfigurationProperties config)
      throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    return new Pkcs11Manager(config);
  }

  @Override
  public boolean isValid(ConfigurationProperties config) {
    return config.containsKey(PKCS11_CONFIG)
        && config.containsKey(PROVIDER_NAME)
        && config.containsKey(KEYSTORE_TYPE)
        && config.getProperty(KEYSTORE_TYPE).equalsIgnoreCase("PKCS11");
  }

  @Override
  protected KeyStore createKeyStore(
      String type, String path, char[] password, ConfigurationProperties config)
      throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    String pkcs11ConfigPath = config.getProperty(PKCS11_CONFIG);
    String providerName = config.getProperty(PROVIDER_NAME);
    String pin = config.getProperty(KEYSTORE_PASSWORD);

    Provider provider = Security.getProvider(providerName);
    if (provider == null) {
      throw new IOException("Provider " + providerName + " not found");
    }
    provider = provider.configure(pkcs11ConfigPath);
    Security.addProvider(provider);
    KeyStore store = KeyStore.getInstance(type, provider);
    store.load(null, pin.toCharArray()); // typically, no IO stream or password is used for PKCS#11 keystores
    return store;
  }

}

