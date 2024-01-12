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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreManager implements CertificateManager {

  private final KeyStore keyStore;
  private final String keyStorePath;
  private final char[] keyStorePassword;

  public KeyStoreManager(String keyStorePath, char[] keyStorePassword) throws Exception {
    this.keyStorePath = keyStorePath;
    this.keyStorePassword = keyStorePassword;
    keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

    // Load the keystore
    try (FileInputStream fis = new FileInputStream(keyStorePath)) {
      keyStore.load(fis, keyStorePassword);
    } catch (IOException e) {
      // If the keystore does not exist, initialize a new one
      keyStore.load(null, null);
    }
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

  private void saveKeyStore() throws CertificateException {
    try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
      keyStore.store(fos, keyStorePassword);
    } catch (IOException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new CertificateException("Error saving keystore", e);
    }
  }
}
