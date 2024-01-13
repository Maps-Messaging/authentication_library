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

package io.mapsmessaging.security.cipher;

import io.mapsmessaging.security.certificates.CertificateManager;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class BufferCipher {

  private static final String RSA_CIPHER_MODE = "RSA/ECB/PKCS1Padding";
  private static final String CIPHER_NAME = "AES";
  private static final int AES_KEY_SIZE = 256;

  private final CertificateManager certManager;

  public BufferCipher(CertificateManager certManager) {
    this.certManager = certManager;
  }

  public byte[] encrypt(String alias, byte[] data) {
    try {
      data = Compressor.compress(data);
      Certificate cert = certManager.getCertificate(alias);
      PublicKey publicKey = cert.getPublicKey();

      // Step 1: Generate AES Key
      KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_NAME);
      keyGenerator.init(AES_KEY_SIZE); // AES key size
      SecretKey aesKey = keyGenerator.generateKey();

      // Step 2: Encrypt the data with AES
      Cipher aesCipher = Cipher.getInstance(CIPHER_NAME);
      aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
      byte[] encryptedData = aesCipher.doFinal(data);

      // Step 3: Encrypt the AES Key with RSA
      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_MODE);
      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey); // publicKey should be RSA Public Key
      byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

      // Step 4: Combine Encrypted AES Key and Encrypted Data
      byte[] combinedOutput = new byte[encryptedAesKey.length + encryptedData.length];
      System.arraycopy(encryptedAesKey, 0, combinedOutput, 0, encryptedAesKey.length);
      System.arraycopy(
          encryptedData, 0, combinedOutput, encryptedAesKey.length, encryptedData.length);
      return combinedOutput;
    } catch (Exception e) {
      throw new RuntimeException("Error encrypting data", e);
    }
  }

  public byte[] decrypt(String alias, byte[] combinedData, char[] password) {
    try {
      PrivateKey privateKey = certManager.getKey(alias, password);
      // Assuming the first 256 bytes (2048 bits) are the RSA-encrypted AES key
      byte[] encryptedAesKey = new byte[AES_KEY_SIZE]; // Adjust size based on RSA key size
      System.arraycopy(combinedData, 0, encryptedAesKey, 0, encryptedAesKey.length);

      // The rest is the AES-encrypted data
      byte[] encryptedData = new byte[combinedData.length - encryptedAesKey.length];
      System.arraycopy(
          combinedData, encryptedAesKey.length, encryptedData, 0, encryptedData.length);

      // Decrypt the AES key
      Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_MODE);
      rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
      byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
      SecretKey aesKey = new SecretKeySpec(aesKeyBytes, CIPHER_NAME);

      // Decrypt the data
      Cipher aesCipher = Cipher.getInstance(CIPHER_NAME);
      aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
      return Decompressor.decompress(aesCipher.doFinal(encryptedData));
    } catch (Exception e) {
      throw new RuntimeException("Error decrypting data", e);
    }
  }
}
