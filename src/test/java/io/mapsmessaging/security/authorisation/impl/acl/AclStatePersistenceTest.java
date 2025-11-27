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

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class AclStatePersistenceTest {

  private SecretKey createTestKey() {
    byte[] keyBytes = new byte[32];
    for (int index = 0; index < keyBytes.length; index++) {
      keyBytes[index] = (byte) index;
    }
    return new SecretKeySpec(keyBytes, "AES");
  }

  @Test
  void testRoundTripSaveAndLoad() throws Exception {
    SecretKey secretKey = createTestKey();
    Path tempFile = Files.createTempFile("acl-state", ".dat");
    String filePath = tempFile.toAbsolutePath().toString();

    String originalJson = """
        {
          "version": 1,
          "entries": []
        }
        """;

    AclSaveState saveState = new AclSaveState(filePath, secretKey);
    saveState.saveState(originalJson);

    AclLoadState loadState = new AclLoadState(filePath, secretKey);
    String loadedJson = loadState.loadState();

    assertNotNull(loadedJson);
    assertEquals(originalJson.replace("\r\n", "\n").trim(),
        loadedJson.replace("\r\n", "\n").trim());
  }

  @Test
  void testLoadStateWhenFileMissingReturnsEmptyString() throws Exception {
    SecretKey secretKey = createTestKey();
    Path tempFile = Files.createTempFile("acl-state-missing", ".dat");
    Files.deleteIfExists(tempFile);

    String filePath = tempFile.toAbsolutePath().toString();

    AclLoadState loadState = new AclLoadState(filePath, secretKey);
    String loadedJson = loadState.loadState();

    assertNotNull(loadedJson);
    assertEquals("", loadedJson, "Missing file should be treated as empty state");
  }

  @Test
  void testLoadStateWithCorruptFileReturnsEmptyString() throws Exception {
    SecretKey secretKey = createTestKey();
    Path tempFile = Files.createTempFile("acl-state-corrupt", ".dat");
    String filePath = tempFile.toAbsolutePath().toString();

    byte[] garbage = new byte[] {1, 2, 3, 4, 5};
    Files.write(tempFile, garbage);

    AclLoadState loadState = new AclLoadState(filePath, secretKey);
    try{
      String loadedJson = loadState.loadState();
      fail("should have thrown an GeneralSecurityException");
    }
    catch(GeneralSecurityException e){
      // Expected
    }
  }
}