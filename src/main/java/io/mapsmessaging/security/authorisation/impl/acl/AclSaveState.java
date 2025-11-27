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

package io.mapsmessaging.security.authorisation.impl.acl;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.zip.GZIPOutputStream;

public class AclSaveState {

  private final String filepath;
  private final SecretKey encryptionKey;

  public AclSaveState(String filepath, SecretKey encryptionKey) {
    this.filepath = filepath;
    this.encryptionKey = encryptionKey;
    Objects.requireNonNull(filepath, "filePath");
    Objects.requireNonNull(encryptionKey, "encryptionKey");
  }

  public void saveState(String data) throws IOException, GeneralSecurityException {
    Objects.requireNonNull(data, "data");
    byte[] compressedData = compressData(data);
    byte[] encryptedData = encryptAesGcm(compressedData);

    Path path = Path.of(filepath);
    Files.write(path, encryptedData);
  }

  private byte[] compressData(String data) throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)) {
      byte[] inputBytes = data.getBytes(StandardCharsets.UTF_8);
      gzipOutputStream.write(inputBytes);
      gzipOutputStream.finish();
    }
    return byteArrayOutputStream.toByteArray();
  }

  private byte[] encryptAesGcm(byte[] input) throws GeneralSecurityException {
    byte[] initializationVector = new byte[12];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(initializationVector);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, initializationVector);
    cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmParameterSpec);

    byte[] cipherText = cipher.doFinal(input);

    byte[] output = new byte[initializationVector.length + cipherText.length];
    System.arraycopy(initializationVector, 0, output, 0, initializationVector.length);
    System.arraycopy(cipherText, 0, output, initializationVector.length, cipherText.length);

    return output;
  }
}
