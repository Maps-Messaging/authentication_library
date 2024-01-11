/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.pkcs11;


import java.security.*;
import java.security.cert.Certificate;

public class Pkcs11Manager {
  private final String pkcs11ConfigPath;
  private KeyStore keyStore;
  private final String providerName;

  public Pkcs11Manager(String pkcs11ConfigPath, String providerName) {
    this.pkcs11ConfigPath = pkcs11ConfigPath;
    this.providerName = providerName;
    initializeKeyStore();
  }

  private void initializeKeyStore() {
    try {
      Provider provider = Security.getProvider(providerName);
      provider = provider.configure(pkcs11ConfigPath);
      Security.addProvider(provider);
      this.keyStore = KeyStore.getInstance("PKCS11", provider);
      keyStore.load(null, null); // typically, no IO stream or password is used for PKCS#11 keystores
    } catch (Exception e) {
      throw new RuntimeException("Error initializing PKCS#11 Keystore", e);
    }
  }

  public Certificate getCertificate(String alias) {
    try {
      if (!keyStore.containsAlias(alias)) {
        throw new KeyStoreException("Alias does not exist");
      }
      return keyStore.getCertificate(alias);
    } catch (KeyStoreException e) {
      throw new RuntimeException("Error retrieving certificate", e);
    }
  }

  public void deleteCertificate(String alias) {
    try {
      if (!keyStore.containsAlias(alias)) {
        throw new KeyStoreException("Alias does not exist");
      }
      keyStore.deleteEntry(alias);
    } catch (KeyStoreException e) {
      throw new RuntimeException("Error retrieving certificate", e);
    }
  }

  public void storeCertificate(String alias, Certificate cert) {
    try {
      if (keyStore.containsAlias(alias)) {
        throw new KeyStoreException("Alias already exist");
      }
      keyStore.setCertificateEntry(alias, cert);
    } catch (KeyStoreException e) {
      throw new RuntimeException("Error storing certificate", e);
    }
  }

  public Object getKey(String alias, char[] password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
    return keyStore.getKey(alias, password);
  }
}

