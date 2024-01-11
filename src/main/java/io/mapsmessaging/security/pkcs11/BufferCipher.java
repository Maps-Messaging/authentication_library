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

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class BufferCipher {

  private final Pkcs11Manager pkcs11Manager;

  private final String encryptionAlgorithm;

  public BufferCipher(Pkcs11Manager pkcs11Manager, String encryptionAlgorithm) {
    this.pkcs11Manager = pkcs11Manager;
    this.encryptionAlgorithm = encryptionAlgorithm;
  }

  public byte[] encrypt(String alias, byte[] data) {
    try {
      Certificate cert = pkcs11Manager.getCertificate(alias);
      PublicKey publicKey = cert.getPublicKey();

      Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      return cipher.doFinal(data);
    } catch (Exception e) {
      throw new RuntimeException("Error encrypting data", e);
    }
  }

  public byte[] decrypt(String alias, byte[] encryptedData, char[] password) {
    try {
      PrivateKey privateKey = (PrivateKey) pkcs11Manager.getKey(alias, password);
      Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      return cipher.doFinal(encryptedData);
    } catch (Exception e) {
      throw new RuntimeException("Error decrypting data", e);
    }
  }
}
