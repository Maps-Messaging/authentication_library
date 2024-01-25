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

package io.mapsmessaging.security.cipher;

import io.mapsmessaging.security.certificates.CertificateManager;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The {@code BufferCipher} class provides functionality for secure encryption and decryption of data,
 * employing a combination of RSA and AES cryptographic algorithms to ensure data confidentiality and integrity.
 *
 * <p>Key functionalities of this class include:
 * <ul>
 *   <li><b>Compression/Decompression:</b> Data is compressed before encryption and decompressed after decryption
 *       to improve efficiency and reduce storage/transmission requirements.</li>
 *   <li><b>RSA Encryption of AES Key and IV:</b> The AES key and initialization vector (IV) are securely
 *       encrypted using RSA with the ECB mode and OAEP padding scheme. The 'RSA/ECB/OAEPWithSHA-256AndMGF1Padding'
 *       mode provides strong security by using OAEP (Optimal Asymmetric Encryption Padding) with SHA-256 hash
 *       function and MGF1 (Mask Generation Function) padding. This method offers better security than traditional
 *       PKCS#1 v1.5 padding and protects against various attacks such as padding oracle attacks.</li>
 *   <li><b>AES Encryption of Data:</b> Data is encrypted using the AES algorithm in GCM (Galois/Counter Mode) with
 *       'AES/GCM/NoPadding'. GCM is an authenticated encryption mode that not only ensures confidentiality but also
 *       provides data integrity and authenticity. The 'NoPadding' specification is used as GCM mode handles padding
 *       internally and does not require explicit padding of input data.</li>
 * </ul>
 *
 * <p>Usage of this class involves initializing it with the necessary RSA public/private keys and then
 * using the provided methods for encrypting or decrypting data. The class handles all aspects of the
 * cryptographic process, including key generation, IV generation, and the application of compression algorithms.
 *
 * @author Matthew Buckton
 */

public class BufferCipher {

  private static final String RSA_CIPHER_MODE = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
  private static final String KEY_GENERATOR_ALGORITHM = "AES";
  private static final String CIPHER_NAME = "AES/GCM/NoPadding";
  private static final int AES_KEY_SIZE = 256;
  private static final int AES_BLOCK_SIZE = 16;
  private static final int HEADER_SIZE = 4;

  private final CertificateManager certManager;

  public BufferCipher(CertificateManager certManager) {
    this.certManager = certManager;
  }

  public byte[] encrypt(String alias, byte[] data) throws GeneralSecurityException, IOException {
    Certificate cert = certManager.getCertificate(alias);
    PublicKey publicKey = cert.getPublicKey();

    KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_GENERATOR_ALGORITHM);
    keyGenerator.init(AES_KEY_SIZE);
    SecretKey aesKey = keyGenerator.generateKey();
    byte[] iv = generateIV();

    Cipher aesCipher = initCipher(Cipher.ENCRYPT_MODE, aesKey, iv);
    byte[] encryptedData = aesCipher.doFinal(Compressor.compress(data));

    RsaPartition rsaPartition = new RsaPartition(aesKey, iv);
    byte[] encryptedKeyAndIv = encryptRsaPartition(rsaPartition, publicKey);

    // Prepend the length of the encrypted key and IV
    ByteBuffer buffer = ByteBuffer.allocate(HEADER_SIZE + encryptedKeyAndIv.length + encryptedData.length);
    buffer.putInt(encryptedKeyAndIv.length);
    buffer.put(encryptedKeyAndIv);
    buffer.put(encryptedData);

    return buffer.array();
  }

  public byte[] decrypt(String alias, byte[] data, char[] password)
      throws GeneralSecurityException, IOException {
    PrivateKey privateKey = certManager.getKey(alias, password);
    ByteBuffer buffer = ByteBuffer.wrap(data);

    // Extract the length of the key and IV
    int lengthOfKeyAndIv = buffer.getInt();
    byte[] encryptedKeyAndIv = new byte[lengthOfKeyAndIv];
    buffer.get(encryptedKeyAndIv);

    // The remaining data is the encrypted data
    byte[] encryptedData = new byte[buffer.remaining()];
    buffer.get(encryptedData);

    // Decrypt the AES key and IV
    RsaPartition rsaPartition = decryptRsaPartition(encryptedKeyAndIv, privateKey);

    // Decrypt the data
    Cipher aesCipher = initCipher(Cipher.DECRYPT_MODE, rsaPartition.aesKey, rsaPartition.iv);
    return Decompressor.decompress(aesCipher.doFinal(encryptedData));
  }

  private byte[] generateIV() {
    SecureRandom random = new SecureRandom();
    byte[] iv = new byte[AES_BLOCK_SIZE]; // AES block size in bytes
    random.nextBytes(iv);
    return iv;
  }

  private Cipher initCipher(int mode, SecretKey key, byte[] iv)
      throws NoSuchAlgorithmException,
          NoSuchPaddingException,
          InvalidKeyException,
          InvalidAlgorithmParameterException {
    Cipher cipher = Cipher.getInstance(CIPHER_NAME);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(mode, key, ivSpec);
    return cipher;
  }

  private byte[] encryptRsaPartition(RsaPartition rsaPartition, PublicKey publicKey)
      throws GeneralSecurityException {
    Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_MODE);
    rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return rsaCipher.doFinal(rsaPartition.encode());
  }

  private RsaPartition decryptRsaPartition(byte[] buffer, PrivateKey privateKey) throws GeneralSecurityException {
    Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_MODE);
    rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] decrypted = rsaCipher.doFinal(buffer);

    byte[] aesKeyBytes = new byte[AES_KEY_SIZE >> 3];
    byte[] iv = new byte[decrypted.length - aesKeyBytes.length];
    System.arraycopy(decrypted, 0, aesKeyBytes, 0, aesKeyBytes.length);
    System.arraycopy(decrypted, aesKeyBytes.length, iv, 0, iv.length);

    SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
    return new RsaPartition(aesKey, iv);
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  private static class RsaPartition {
    private SecretKey aesKey;
    private byte[] iv;

    byte[] encode() {
      byte[] aesKeyBytes = aesKey.getEncoded();
      byte[] combined = new byte[aesKeyBytes.length + iv.length];
      System.arraycopy(aesKeyBytes, 0, combined, 0, aesKeyBytes.length);
      System.arraycopy(iv, 0, combined, aesKeyBytes.length, iv.length);
      return combined;
    }
  }
}
