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

package io.mapsmessaging.security.certificates.keystore;

import io.mapsmessaging.security.certificates.CertificateManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Map;
import lombok.Getter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyStoreManager implements CertificateManager {

  protected static final String KEYSTORE_TYPE = "type";
  protected static final String KEYSTORE_PATH = "path";
  protected static final String KEYSTORE_PASSWORD = "passphrase";
  protected static final String PROVIDER_NAME = "providerName";

  @Getter
  private final KeyStore keyStore;
  private final String keyStorePath;
  private final char[] keyStorePassword;
  private final boolean existed;

  public KeyStoreManager() {
    keyStore = null;
    keyStorePath = "";
    keyStorePassword = new char[0];
    existed = true;
  }

  public boolean isValid(Map<String, ?> config) {
    return config.containsKey(KEYSTORE_TYPE) &&
        config.containsKey(KEYSTORE_PASSWORD) &&
        config.containsKey(KEYSTORE_PATH);
  }

  protected KeyStoreManager(Map<String, ?> config) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    String providerName = (String) config.get(PROVIDER_NAME);
    if (providerName != null && !providerName.isEmpty() && "BC".equals(providerName)) {
      Security.addProvider(new BouncyCastleProvider());
    }

    keyStorePath = (String) config.get(KEYSTORE_PATH);
    String t = (String) config.get(KEYSTORE_PASSWORD);
    if (t == null) {
      t = "";
    }
    this.keyStorePassword = t.toCharArray();
    if (keyStorePath != null) {
      File file = new File(keyStorePath);
      existed = file.exists();
    } else {
      existed = true;
    }
    String type = (String) config.get(KEYSTORE_TYPE);
    keyStore = createKeyStore(type, keyStorePath, keyStorePassword, config);
  }

  public CertificateManager create(Map<String, ?> config) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    return new KeyStoreManager(config);
  }

  @SuppressWarnings("java:S1172") // the config parameter is kept since it may or may not be used in extending classes
  protected KeyStore createKeyStore(String type, String path, char[] password, Map<String, ?> config)
      throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    KeyStore store = KeyStore.getInstance(type);
    if (path != null && existed) {
      try (FileInputStream fis = new FileInputStream(path)) {
        store.load(fis, password);
        return store;
      }
    }
    store.load(null, null);
    return store;
  }

  @Override
  public Certificate getCertificate(String alias) throws CertificateException {
    try {
      if (keyStore.containsAlias(alias)) {
        return keyStore.getCertificate(alias);
      }
    } catch (KeyStoreException e) {
      throw new CertificateException("Error retrieving certificate", e);
    }
    throw new CertificateException("Alias does not exist");
  }

  @Override
  public void addCertificate(String alias, Certificate certificate) throws CertificateException {
    try {
      keyStore.setCertificateEntry(alias, certificate);
      saveKeyStore();
    } catch (KeyStoreException e) {
      throw new CertificateException("Error storing certificate", e);
    }
  }

  @Override
  public void deleteCertificate(String alias) throws CertificateException {
    try {
      if (keyStore.containsAlias(alias)) {
        keyStore.deleteEntry(alias);
        saveKeyStore();
      } else {
        throw new KeyStoreException("Alias does not exist");
      }
    } catch (KeyStoreException e) {
      throw new CertificateException("Error deleting certificate", e);
    }
  }

  @Override
  public PrivateKey getKey(String alias, char[] keyPassword) throws CertificateException {
    try {
      Key key = keyStore.getKey(alias, keyPassword);
      if (key instanceof PrivateKey) {
        return (PrivateKey) key;
      } else {
        throw new KeyStoreException("No private key found for alias: " + alias);
      }
    } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new CertificateException(e);
    }
  }

  @Override
  public void addPrivateKey(
      String alias, char[] password, PrivateKey privateKey, Certificate[] certChain)
      throws CertificateException {
    try {
      keyStore.setKeyEntry(alias, privateKey, password, certChain);
      saveKeyStore();
    } catch (KeyStoreException e) {
      throw new CertificateException("Exception saving private key", e);
    }
  }

  @Override
  public boolean getExists() {
    return existed;
  }

  private void saveKeyStore() throws CertificateException {
    try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
      keyStore.store(fos, keyStorePassword);
    } catch (IOException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new CertificateException("Error saving keystore", e);
    }
  }
}
