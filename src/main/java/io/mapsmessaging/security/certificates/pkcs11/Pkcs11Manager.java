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

import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.certificates.keystore.KeyStoreManager;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Map;

public class Pkcs11Manager extends KeyStoreManager {

  private static final String PKCS11_CONFIG = "pkcs11.cfg";
  private static final String PROVIDER_NAME = "provider.name";

  public Pkcs11Manager() {
    super();
  }

  protected Pkcs11Manager(Map<String, ?> config) throws Exception {
    super(config);
  }

  @Override
  public CertificateManager create(Map<String, ?> config) throws Exception {
    return new Pkcs11Manager(config);
  }

  public boolean isValid(Map<String, ?> config) {
    return config.containsKey(PKCS11_CONFIG)
        && config.containsKey(PROVIDER_NAME)
        && config.containsKey(KEYSTORE_TYPE)
        && config.get(KEYSTORE_TYPE).toString().equalsIgnoreCase("PKCS11");
  }

  @Override
  protected KeyStore createKeyStore(
      String type, String path, char[] password, Map<String, ?> config)
      throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    String pkcs11ConfigPath = config.get(PKCS11_CONFIG).toString();
    String providerName = config.get(PROVIDER_NAME).toString();

    Provider provider = Security.getProvider(providerName);
    if (provider == null) {
      throw new IOException("Provider " + providerName + " not found");
    }
    provider = provider.configure(pkcs11ConfigPath);
    Security.addProvider(provider);
    KeyStore store = KeyStore.getInstance(type, provider);
    store.load(null, null); // typically, no IO stream or password is used for PKCS#11 keystores
    return store;
  }

}

