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
import lombok.Getter;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Map;

public class Pkcs11Manager implements CertificateManager {

  private static final String PKCS11_CONFIG = "pkcs11.cfg";
  private static final String PROVIDER_NAME = "provider.name";

  @Getter
  private KeyStore keyStore;
  private final String pkcs11ConfigPath;
  private final String providerName;

  public Pkcs11Manager() {
    pkcs11ConfigPath = "";
    providerName = "";
  }

  public boolean isValid(Map<String, ?> config) {
    return config.containsKey(PKCS11_CONFIG) &&
        config.containsKey(PROVIDER_NAME);
  }

  @Override
  public CertificateManager create(Map<String, ?> config) throws Exception {
    return new Pkcs11Manager(config);
  }

  protected Pkcs11Manager(Map<String, ?> config) {
    this.pkcs11ConfigPath = config.get(PKCS11_CONFIG).toString();
    this.providerName = config.get(PROVIDER_NAME).toString();
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

  public void addCertificate(String alias, Certificate cert) {
    try {
      if (keyStore.containsAlias(alias)) {
        throw new KeyStoreException("Alias already exist");
      }
      keyStore.setCertificateEntry(alias, cert);
    } catch (KeyStoreException e) {
      throw new RuntimeException("Error storing certificate", e);
    }
  }

  public PrivateKey getKey(String alias, char[] password) throws CertificateException {
    try {
      return (PrivateKey) keyStore.getKey(alias, password);
    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
      throw new CertificateException(e);
    }
  }

  @Override
  public void addPrivateKey(
      String alias, char[] password, PrivateKey privateKey, Certificate[] certChain)
      throws CertificateException {
    try {
      keyStore.setKeyEntry(alias, privateKey, password, certChain);
    } catch (KeyStoreException e) {
      throw new CertificateException(e);
    }
  }
}

