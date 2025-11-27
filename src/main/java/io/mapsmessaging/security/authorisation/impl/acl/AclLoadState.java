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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.zip.GZIPInputStream;

public class AclLoadState {

  private static final int GCM_TAG_LENGTH_BITS = 128;
  private static final int GCM_IV_LENGTH_BYTES = 12;

  private final String filepath;
  private final SecretKey encryptionKey;

  public AclLoadState(String filepath, SecretKey encryptionKey) {
    this.filepath = filepath;
    this.encryptionKey = encryptionKey;
    Objects.requireNonNull(filepath, "filePath");
    Objects.requireNonNull(encryptionKey, "encryptionKey");
  }

  public String loadState() throws IOException, GeneralSecurityException {
    Path path = Path.of(filepath);
    if(!Files.exists(path)){
      return "";
    }
    byte[] fileBytes = Files.readAllBytes(path);

    if (fileBytes.length <= GCM_IV_LENGTH_BYTES) {
      throw new GeneralSecurityException("Encrypted ACL state is too short");
    }

    byte[] initializationVector = Arrays.copyOfRange(fileBytes, 0, GCM_IV_LENGTH_BYTES);
    byte[] cipherText = Arrays.copyOfRange(fileBytes, GCM_IV_LENGTH_BYTES, fileBytes.length);

    byte[] compressedData = decryptAesGcm(cipherText, initializationVector);
    return decompressData(compressedData);
  }

  private byte[] decryptAesGcm(byte[] cipherText,
                               byte[] initializationVector) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, initializationVector);
    cipher.init(Cipher.DECRYPT_MODE, encryptionKey, gcmParameterSpec);
    return cipher.doFinal(cipherText);
  }

  private String decompressData(byte[] compressedData) throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try (GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData))) {
      byte[] buffer = new byte[4096];
      int bytesRead;
      while ((bytesRead = gzipInputStream.read(buffer)) != -1) {
        byteArrayOutputStream.write(buffer, 0, bytesRead);
      }
    }
    return byteArrayOutputStream.toString(StandardCharsets.UTF_8);
  }
}
